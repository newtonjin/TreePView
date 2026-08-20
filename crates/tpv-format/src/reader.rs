//! Reading a `.tpv` case.
//!
//! Every expensive operation the viewer needs happens here, in Rust, against
//! SQLite indexes: filtering, aggregation and time binning. The frontend
//! receives only what it draws. That split is the whole reason a case with
//! millions of events can feel immediate — the alternative, shipping rows to
//! JavaScript and filtering there, stops working around a hundred thousand.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, ToSql};
use tpv_model::{
    time::{TsFlags, TsPrecision, TzSource},
    AccessMethod, CollectionProfile, Confidence, Custody, EventKind, Finding, HostInfo,
    ManifestEntry, ReferenceClock, Severity, Source, Timestamp, FORMAT_VERSION,
};

use crate::blob::{BlobInfo, BlobReader};
use crate::error::{FormatError, Result};
use crate::schema;

/// Case-level metadata, read once when the viewer opens a file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CaseMeta {
    pub format_version: u32,
    pub case_id: String,
    pub tool_version: String,
    pub created_utc_ns: i64,
    pub host: HostInfo,
    pub clock: ReferenceClock,
    pub profile: CollectionProfile,
    pub custody: Option<Custody>,
    /// False when the collection was interrupted. The case is still readable;
    /// the flag exists so the analyst knows the evidence may be partial rather
    /// than concluding an artifact was absent.
    pub finalized: bool,
    pub content_digest: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct Counts {
    pub events: i64,
    pub entities: i64,
    pub edges: i64,
    pub blobs: i64,
    pub manifest_entries: i64,
    pub findings: i64,
}

/// One row of the timeline, as the viewer displays it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct EventRow {
    pub id: i64,
    pub ts: Timestamp,
    /// The instant rendered as RFC 3339 here, where `utc_ns` is still an exact
    /// integer. A frontend cannot do this: past 2004 the value exceeds
    /// JavaScript's 2^53 exact range and would display up to 256 ns off.
    pub iso: String,
    pub ts_end_utc_ns: Option<i64>,
    pub source: String,
    pub kind: String,
    pub entity_key: Option<String>,
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub image: Option<String>,
    pub user: Option<String>,
    pub path: Option<String>,
    pub remote: Option<String>,
    /// Windows Event ID / Sysmon ID when the case stored one.
    pub log_id: Option<u32>,
    pub summary: String,
    pub has_payload: bool,
}

/// When a process began, and how sure we are of it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ProcessStart {
    pub ns: i64,
    /// Formatted here because i64 nanoseconds are not exactly representable in
    /// the viewer's frontend.
    pub iso: String,
    /// False when the creation time could not be read and this is merely the
    /// first moment the process was observed. A lineage view that presents the
    /// two identically would invite an analyst to read collection order as
    /// execution order.
    pub exact: bool,
}

/// A node of the process tree.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ProcessNode {
    pub entity_id: i64,
    pub key: String,
    /// Deterministic ULID of this execution. PID is displayed; this is identity.
    #[serde(default)]
    pub instance_id: String,
    pub label: String,
    pub pid: Option<u32>,
    pub started: Option<ProcessStart>,
    /// Denormalized onto the node so the tree can show and search the fields an
    /// analyst actually triages on. A command line hidden one click away inside
    /// an attribute blob is a command line nobody reads.
    pub image: Option<String>,
    pub command_line: Option<String>,
    pub user: Option<String>,
    pub elevated: Option<bool>,
    /// Why this process could not be fully inspected, when it could not be.
    pub access_error: Option<String>,
    pub event_count: i64,
    pub first_event_ns: Option<i64>,
    pub last_event_ns: Option<i64>,
    /// Highest finding severity attached to this process, for tree decoration.
    pub max_severity: Option<Severity>,
    /// `root` | `confirmed` | `inferred` | `orphaned` | `impossible`.
    #[serde(default = "default_parent_edge")]
    pub parent_edge: String,
    pub claimed_ppid: Option<u32>,
    #[serde(default)]
    pub source_set: Vec<String>,
    #[serde(default)]
    pub indicators: Vec<String>,
    /// Event-log rows that belong on this process's branch (4688, logon, net…).
    #[serde(default)]
    pub related_logs: Vec<RelatedLog>,
    /// How many further correlated logs were omitted (cap, not missing evidence).
    #[serde(default)]
    pub related_logs_omitted: i64,
    pub children: Vec<ProcessNode>,
}

/// A Windows Event Log / Sysmon row hanging off a process in the tree.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RelatedLog {
    pub event_id: i64,
    pub log_id: Option<u32>,
    pub kind: String,
    pub source: String,
    pub iso: String,
    pub summary: String,
    pub ts_ns: i64,
}

#[allow(dead_code)]
fn default_parent_edge() -> String {
    "root".into()
}

/// An entity as the inspector shows it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct EntityRow {
    pub id: i64,
    pub kind: String,
    pub key: String,
    pub label: String,
    /// Earliest well-formed event referring to this entity.
    pub first_seen_ns: Option<i64>,
    pub event_count: i64,
    pub attrs: Option<serde_json::Value>,
}

/// An entity reachable from another one, with the relation that connects them.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RelatedEntity {
    pub kind: String,
    pub entity: EntityRow,
    /// True when the inspected entity is the source of the edge.
    pub outgoing: bool,
}

/// One bucket of the zoomed-out timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct TimeBin {
    pub index: u32,
    pub start_ns: i64,
    pub end_ns: i64,
    pub count: i64,
}

/// One named band of the stacked timeline.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LaneSeries {
    pub lane: String,
    pub bins: Vec<TimeBin>,
}

/// Which events to consider. Every field narrows; an empty filter matches all.
/// Deserializable so the viewer frontend can hand a filter straight to the
/// backend. Every field defaults, so the frontend sends only what it constrains
/// and adding a dimension here does not break an older frontend.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct EventFilter {
    pub from_ns: Option<i64>,
    pub to_ns: Option<i64>,
    pub pids: Vec<u32>,
    pub sources: Vec<Source>,
    pub kinds: Vec<EventKind>,
    /// Drop these kinds. Used to keep module loads and live snapshots off the
    /// default timeline so Event IDs are actually visible.
    pub exclude_kinds: Vec<EventKind>,
    pub entity_key: Option<String>,
    /// Exact event ids, used to re-fetch a selection.
    pub event_ids: Vec<i64>,
    /// Full-text query against summary, image, path, remote and user.
    pub text: Option<String>,
    /// Substring match on the image path.
    pub image_contains: Option<String>,
    pub path_contains: Option<String>,
    pub remote_contains: Option<String>,
    pub user_contains: Option<String>,
    pub source_contains: Option<String>,
    pub kind_contains: Option<String>,
    pub summary_contains: Option<String>,
    /// Substring match on the PID rendered as decimal text, so typing `12`
    /// finds 12, 120 and 412 rather than requiring an exact id.
    pub pid_contains: Option<String>,
    /// Exact Windows Event IDs / Sysmon IDs (`id:4688`).
    pub log_ids: Vec<u32>,
    /// Substring on the Event ID rendered as decimal text, so `46` finds 4688.
    pub log_id_contains: Option<String>,
    /// Restrict to Windows event logs and Linux journal/audit records.
    pub logs_only: bool,
    /// Restrict to events that have a network peer.
    pub network_only: bool,
    /// Restrict to events whose timestamp was clamped, zeroed or inferred.
    pub suspect_time_only: bool,
    pub min_severity: Option<Severity>,
    /// Hunt paste: one IOC per line (hash, IP, filename, `id:4688`). Combined
    /// with OR, then AND-ed with the rest of the filter.
    pub iocs: Vec<String>,
}

impl EventFilter {
    pub fn in_range(from_ns: i64, to_ns: i64) -> Self {
        Self {
            from_ns: Some(from_ns),
            to_ns: Some(to_ns),
            ..Default::default()
        }
    }

    /// Render the filter as a SQL predicate plus its bound parameters.
    ///
    /// Built by concatenating placeholders and pushing values, never by
    /// interpolating analyst input into SQL. A case file is untrusted input:
    /// the paths and command lines inside it came from a machine an adversary
    /// may have controlled.
    fn to_sql(&self, has_log_id: bool) -> (String, Vec<Box<dyn ToSql>>) {
        let mut clauses: Vec<String> = vec!["1=1".into()];
        let mut args: Vec<Box<dyn ToSql>> = Vec::new();

        if let Some(from) = self.from_ns {
            clauses.push("e.ts_utc_ns >= ?".into());
            args.push(Box::new(from));
        }
        if let Some(to) = self.to_ns {
            clauses.push("e.ts_utc_ns <= ?".into());
            args.push(Box::new(to));
        }
        if !self.pids.is_empty() {
            let ph = vec!["?"; self.pids.len()].join(",");
            clauses.push(format!("e.pid IN ({ph})"));
            for p in &self.pids {
                args.push(Box::new(*p as i64));
            }
        }
        if !self.sources.is_empty() {
            let ph = vec!["?"; self.sources.len()].join(",");
            clauses.push(format!("e.source IN ({ph})"));
            for s in &self.sources {
                args.push(Box::new(s.as_str().to_string()));
            }
        }
        if !self.kinds.is_empty() {
            let ph = vec!["?"; self.kinds.len()].join(",");
            clauses.push(format!("e.kind IN ({ph})"));
            for k in &self.kinds {
                args.push(Box::new(k.as_str().to_string()));
            }
        }
        if !self.exclude_kinds.is_empty() {
            let ph = vec!["?"; self.exclude_kinds.len()].join(",");
            clauses.push(format!("e.kind NOT IN ({ph})"));
            for k in &self.exclude_kinds {
                args.push(Box::new(k.as_str().to_string()));
            }
        }
        if let Some(key) = &self.entity_key {
            // A pinned live process should also show event-log rows that share
            // its PID: 4688 / Sysmon 1 are stored with a pid but not the live
            // process's creation-time key, and hiding them on pin would make
            // the log view look empty for the process the analyst just chose.
            if let Some(pid) = pid_from_process_key(key) {
                clauses.push(
                    "(e.entity_id = (SELECT id FROM entities WHERE key = ?) OR e.pid = ?)"
                        .into(),
                );
                args.push(Box::new(key.clone()));
                args.push(Box::new(pid as i64));
            } else {
                clauses
                    .push("e.entity_id = (SELECT id FROM entities WHERE key = ?)".into());
                args.push(Box::new(key.clone()));
            }
        }
        if !self.event_ids.is_empty() {
            let ph = vec!["?"; self.event_ids.len()].join(",");
            clauses.push(format!("e.id IN ({ph})"));
            for id in &self.event_ids {
                args.push(Box::new(*id));
            }
        }
        let mut extra_log_ids = self.log_ids.clone();
        if let Some(t) = &self.text {
            let parsed = parse_search(t);
            extra_log_ids.extend(parsed.log_ids.iter().copied());
            push_parsed_search(&mut clauses, &mut args, &parsed, has_log_id);
        }
        extra_log_ids.sort_unstable();
        extra_log_ids.dedup();
        push_log_ids(&mut clauses, &mut args, &extra_log_ids, has_log_id);
        like_clause(&mut clauses, &mut args, "e.image", self.image_contains.as_deref());
        like_clause(&mut clauses, &mut args, "e.path", self.path_contains.as_deref());
        like_clause(&mut clauses, &mut args, "e.remote", self.remote_contains.as_deref());
        like_clause(&mut clauses, &mut args, "e.user", self.user_contains.as_deref());
        like_clause(&mut clauses, &mut args, "e.source", self.source_contains.as_deref());
        like_clause(&mut clauses, &mut args, "e.kind", self.kind_contains.as_deref());
        like_clause(&mut clauses, &mut args, "e.summary", self.summary_contains.as_deref());
        if let Some(s) = nonempty(self.pid_contains.as_deref()) {
            clauses.push("CAST(e.pid AS TEXT) LIKE ? ESCAPE '\\'".into());
            args.push(Box::new(format!("%{}%", escape_like(s))));
        }
        push_log_id_contains(&mut clauses, &mut args, self.log_id_contains.as_deref(), has_log_id);
        if self.logs_only {
            clauses.push("e.source IN ('evtx', 'journald', 'auditd')".into());
        }
        if self.network_only {
            // Listeners have no peer, so `remote IS NOT NULL` would hide every
            // bind. Kind covers both directions; the remote clause keeps older
            // cases that recorded a peer without a net_* kind.
            clauses.push(
                "(e.kind IN ('net_connection', 'net_listen') OR e.remote IS NOT NULL)".into(),
            );
        }
        if self.suspect_time_only {
            clauses.push("e.ts_flags != 0".into());
        }
        if let Some(sev) = self.min_severity {
            let allowed: Vec<&str> = [
                Severity::Info,
                Severity::Low,
                Severity::Medium,
                Severity::High,
                Severity::Critical,
            ]
            .iter()
            .filter(|s| s.rank() >= sev.rank())
            .map(|s| s.as_str())
            .collect();
            let ph = vec!["?"; allowed.len()].join(",");
            clauses.push(format!(
                "e.id IN (SELECT fe.event_id FROM finding_evidence fe
                          JOIN findings f ON f.id = fe.finding_id
                          WHERE f.severity IN ({ph}))"
            ));
            for a in allowed {
                args.push(Box::new(a.to_string()));
            }
        }
        let ioc_lines: Vec<&str> = self
            .iocs
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        if !ioc_lines.is_empty() {
            let mut groups = Vec::new();
            for line in ioc_lines {
                let parsed = parse_search(line);
                let mut sub: Vec<String> = Vec::new();
                push_parsed_search(&mut sub, &mut args, &parsed, has_log_id);
                push_log_ids(&mut sub, &mut args, &parsed.log_ids, has_log_id);
                if !sub.is_empty() {
                    groups.push(format!("({})", sub.join(" AND ")));
                }
            }
            if !groups.is_empty() {
                clauses.push(format!("({})", groups.join(" OR ")));
            }
        }

        (clauses.join(" AND "), args)
    }
}

/// SQL restricting to timestamps that can be placed on the axis.
///
/// Kept as one constant so the axis bounds, the per-process first/last times and
/// anything added later cannot drift apart and disagree about which events are
/// on the timeline.
const PLACEABLE: &str = "WHERE ts_flags & 3 = 0";

const _: () = assert!(
    tpv_model::TsFlags::UNPLACEABLE.0 == 3,
    "PLACEABLE hard-codes this mask; update both together"
);

/// Escape LIKE wildcards so a path containing `%` or `_` matches literally.
fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

fn nonempty(s: Option<&str>) -> Option<&str> {
    s.map(str::trim).filter(|s| !s.is_empty())
}

fn like_clause(
    clauses: &mut Vec<String>,
    args: &mut Vec<Box<dyn ToSql>>,
    column: &str,
    value: Option<&str>,
) {
    if let Some(s) = nonempty(value) {
        clauses.push(format!("{column} LIKE ? ESCAPE '\\'"));
        args.push(Box::new(format!("%{}%", escape_like(s))));
    }
}

/// `proc:<pid>:<start>` / `proc:<pid>:unknown` as used by [`tpv_model::ProcessKey`].
fn pid_from_process_key(key: &str) -> Option<u32> {
    let rest = key.strip_prefix("proc:")?;
    rest.split(':').next()?.parse().ok()
}

/// EVTX summaries are `[4688] cmd.exe started`. Recover the id when the column
/// was not stored (older cases, or a parser that only put it in the text).
pub(crate) fn parse_bracket_id(summary: &str) -> Option<u32> {
    let rest = summary.strip_prefix('[')?;
    let (num, _) = rest.split_once(']')?;
    num.parse().ok()
}

/// Turn analyst input into a safe FTS5 query.
///
/// What an analyst types into a search box is a filename, a path or an IP, not
/// an FTS5 expression. Passing it through raw means `evil.exe` is a syntax
/// error and `C:\Users\Public` is worse, so every token is quoted as a literal
/// and the tokens are combined with AND. A trailing `*` is kept outside the
/// quotes so prefix search still works, which is the one operator that is worth
/// the ambiguity.
///
/// Returns `None` when the input has no searchable content, so an all-whitespace
/// query matches everything rather than nothing.
fn fts_query(input: &str) -> Option<String> {
    let terms: Vec<String> = input
        .split_whitespace()
        .filter_map(|raw| {
            let (body, prefix) = match raw.strip_suffix('*') {
                Some(stem) => (stem, true),
                None => (raw, false),
            };
            if body.is_empty() {
                return None;
            }
            let quoted = format!("\"{}\"", body.replace('"', "\"\""));
            Some(if prefix { format!("{quoted}*") } else { quoted })
        })
        .collect();

    if terms.is_empty() {
        None
    } else {
        Some(terms.join(" AND "))
    }
}

#[derive(Default)]
struct ParsedSearch {
    fts: String,
    log_ids: Vec<u32>,
    bare_nums: Vec<u32>,
    pids: Vec<u32>,
    users: Vec<String>,
    channels: Vec<String>,
    kinds: Vec<String>,
    images: Vec<String>,
    remotes: Vec<String>,
    sources: Vec<String>,
}

/// Split a search box into field prefixes and leftover full-text tokens.
///
/// `id:4688`, `eid:1`, `pid:1234`, `user:SYSTEM`, `channel:Security` are
/// exact-field filters. A bare number is Event ID *or* PID *or* text. A token
/// like `C:\Windows` is not a prefix: the key would be a single letter.
fn parse_search(input: &str) -> ParsedSearch {
    let mut out = ParsedSearch::default();
    let mut fts_parts = Vec::new();
    for raw in input.split_whitespace() {
        if let Some((key, rest)) = split_prefix(raw) {
            match key {
                "id" | "eid" | "eventid" | "event_id" | "event" => {
                    out.log_ids.extend(parse_id_list(rest));
                }
                "pid" => out.pids.extend(parse_id_list(rest)),
                "user" | "account" => {
                    if !rest.is_empty() {
                        out.users.push(rest.to_string());
                    }
                }
                "channel" | "log" => {
                    if !rest.is_empty() {
                        out.channels.push(rest.to_string());
                    }
                }
                "kind" => {
                    if !rest.is_empty() {
                        out.kinds.push(rest.to_string());
                    }
                }
                "image" | "process" | "proc" => {
                    if !rest.is_empty() {
                        out.images.push(rest.to_string());
                    }
                }
                "ip" | "remote" | "peer" => {
                    if !rest.is_empty() {
                        out.remotes.push(rest.to_string());
                    }
                }
                "src" | "source" => {
                    if !rest.is_empty() {
                        out.sources.push(rest.to_string());
                    }
                }
                _ => fts_parts.push(raw.to_string()),
            }
        } else if let Some(n) = parse_bare_id(raw) {
            out.bare_nums.push(n);
        } else {
            fts_parts.push(raw.to_string());
        }
    }
    out.fts = fts_parts.join(" ");
    out
}

fn split_prefix(token: &str) -> Option<(&str, &str)> {
    let (key, rest) = token.split_once(':')?;
    if key.len() < 2 || rest.is_empty() {
        return None;
    }
    if !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    Some((key, rest))
}

fn parse_id_list(s: &str) -> Vec<u32> {
    s.split(',')
        .filter_map(|p| p.trim().parse::<u32>().ok())
        .collect()
}

fn parse_bare_id(s: &str) -> Option<u32> {
    if s.len() > 10 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn push_parsed_search(
    clauses: &mut Vec<String>,
    args: &mut Vec<Box<dyn ToSql>>,
    parsed: &ParsedSearch,
    has_log_id: bool,
) {
    if let Some(q) = fts_query(&parsed.fts) {
        clauses.push("e.id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)".into());
        args.push(Box::new(q));
    }
    if !parsed.pids.is_empty() {
        let ph = vec!["?"; parsed.pids.len()].join(",");
        clauses.push(format!("e.pid IN ({ph})"));
        for p in &parsed.pids {
            args.push(Box::new(*p as i64));
        }
    }
    for s in &parsed.users {
        like_clause(clauses, args, "e.user", Some(s));
    }
    for s in &parsed.channels {
        like_clause(clauses, args, "e.path", Some(s));
    }
    for s in &parsed.kinds {
        like_clause(clauses, args, "e.kind", Some(s));
    }
    for s in &parsed.images {
        like_clause(clauses, args, "e.image", Some(s));
    }
    for s in &parsed.remotes {
        like_clause(clauses, args, "e.remote", Some(s));
    }
    for s in &parsed.sources {
        like_clause(clauses, args, "e.source", Some(s));
    }
    if !parsed.bare_nums.is_empty() {
        let mut ors: Vec<String> = Vec::new();
        for n in &parsed.bare_nums {
            ors.push("e.pid = ?".into());
            args.push(Box::new(*n as i64));
            push_log_id_eq_term(&mut ors, args, *n, has_log_id);
            if let Some(q) = fts_query(&n.to_string()) {
                ors.push("e.id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)".into());
                args.push(Box::new(q));
            }
        }
        clauses.push(format!("({})", ors.join(" OR ")));
    }
}

fn push_log_ids(
    clauses: &mut Vec<String>,
    args: &mut Vec<Box<dyn ToSql>>,
    ids: &[u32],
    has_log_id: bool,
) {
    if ids.is_empty() {
        return;
    }
    if has_log_id {
        let ph = vec!["?"; ids.len()].join(",");
        clauses.push(format!("e.log_id IN ({ph})"));
        for id in ids {
            args.push(Box::new(*id as i64));
        }
        return;
    }
    let mut ors = Vec::new();
    for id in ids {
        push_log_id_eq_term(&mut ors, args, *id, false);
    }
    clauses.push(format!("({})", ors.join(" OR ")));
}

fn push_log_id_eq_term(
    ors: &mut Vec<String>,
    args: &mut Vec<Box<dyn ToSql>>,
    id: u32,
    has_log_id: bool,
) {
    if has_log_id {
        ors.push("e.log_id = ?".into());
        args.push(Box::new(id as i64));
    } else {
        ors.push("e.summary LIKE ? ESCAPE '\\'".into());
        args.push(Box::new(format!("[{id}]%")));
    }
}

fn push_log_id_contains(
    clauses: &mut Vec<String>,
    args: &mut Vec<Box<dyn ToSql>>,
    value: Option<&str>,
    has_log_id: bool,
) {
    let Some(s) = nonempty(value) else {
        return;
    };
    if has_log_id {
        clauses.push("CAST(e.log_id AS TEXT) LIKE ? ESCAPE '\\'".into());
        args.push(Box::new(format!("%{}%", escape_like(s))));
    } else {
        clauses.push("e.summary LIKE ? ESCAPE '\\'".into());
        args.push(Box::new(format!("[{}%", escape_like(s))));
    }
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for name in names {
        if name? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

pub struct CaseReader {
    conn: Connection,
    path: PathBuf,
    has_log_id: bool,
}

impl CaseReader {
    /// Open a case read-only.
    ///
    /// Read-only at the SQLite level, not merely by convention: a viewer must
    /// not be capable of modifying evidence. The findings table is the one
    /// exception, and it requires [`Self::open_for_findings`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
    }

    /// Open with write access limited to regenerating derived findings.
    pub fn open_for_findings(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
    }

    fn open_with_flags(path: impl AsRef<Path>, flags: OpenFlags) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let conn = Connection::open_with_flags(&path, flags | OpenFlags::SQLITE_OPEN_URI)?;

        let app_id: i32 = conn.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        if app_id != schema::APPLICATION_ID {
            return Err(FormatError::NotACase {
                path,
                found: app_id,
            });
        }

        let has_log_id = column_exists(&conn, "events", "log_id")?;
        let reader = Self { conn, path, has_log_id };
        let version = reader
            .meta_str(schema::META_FORMAT_VERSION)?
            .ok_or(FormatError::MissingMeta(schema::META_FORMAT_VERSION))?
            .parse::<u32>()
            .unwrap_or(u32::MAX);
        if version > FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion {
                found: version,
                supported: FORMAT_VERSION,
            });
        }
        Ok(reader)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn meta_str(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get::<_, String>(0)
            })
            .optional()?)
    }

    pub fn meta(&self) -> Result<CaseMeta> {
        let need = |k: &'static str| -> Result<String> {
            self.meta_str(k)?.ok_or(FormatError::MissingMeta(k))
        };

        Ok(CaseMeta {
            format_version: need(schema::META_FORMAT_VERSION)?.parse().unwrap_or(0),
            case_id: need(schema::META_CASE_ID)?,
            tool_version: need(schema::META_TOOL_VERSION)?,
            created_utc_ns: need(schema::META_CREATED_NS)?.parse().unwrap_or(0),
            host: serde_json::from_str(&need(schema::META_HOST)?)?,
            clock: serde_json::from_str(&need(schema::META_CLOCK)?)?,
            profile: serde_json::from_str(&need(schema::META_PROFILE)?)?,
            custody: match self.meta_str(schema::META_CUSTODY)? {
                Some(s) => Some(serde_json::from_str(&s)?),
                None => None,
            },
            finalized: self
                .meta_str(schema::META_FINALIZED)?
                .map(|s| s == "1")
                .unwrap_or(false),
            content_digest: self.meta_str(schema::META_CONTENT_DIGEST)?,
        })
    }

    pub fn counts(&self) -> Result<Counts> {
        let one = |sql: &str| -> Result<i64> { Ok(self.conn.query_row(sql, [], |r| r.get(0))?) };
        Ok(Counts {
            events: one("SELECT COUNT(*) FROM events")?,
            entities: one("SELECT COUNT(*) FROM entities")?,
            edges: one("SELECT COUNT(*) FROM edges")?,
            blobs: one("SELECT COUNT(*) FROM blobs")?,
            manifest_entries: one("SELECT COUNT(*) FROM manifest")?,
            findings: one("SELECT COUNT(*) FROM findings")?,
        })
    }

    /// Earliest and latest event timestamps, which bound the timeline axis.
    pub fn time_span(&self) -> Result<Option<(i64, i64)>> {
        // Rows with a clamped or absent timestamp would otherwise stretch the
        // axis across six centuries and squash the real activity into one pixel,
        // so they are excluded from the bounds while remaining fully visible in
        // the data. Inferred rows are *not* excluded: they carry the collection
        // instant, which is a real point in time and is typically later than the
        // newest artifact timestamp. Leaving them out would put the entire live
        // snapshot past the right edge of its own timeline.
        let row: Option<(Option<i64>, Option<i64>)> = self
            .conn
            .query_row(
                &format!("SELECT MIN(ts_utc_ns), MAX(ts_utc_ns) FROM events {PLACEABLE}"),
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(match row {
            Some((Some(lo), Some(hi))) => Some((lo, hi)),
            _ => None,
        })
    }

    /// Fetch a page of matching events, newest constraint applied in SQL.
    pub fn events(&self, filter: &EventFilter, limit: u32, offset: u32) -> Result<Vec<EventRow>> {
        let (where_sql, args) = filter.to_sql(self.has_log_id);
        let log_id_sql = if self.has_log_id { "e.log_id" } else { "NULL" };
        let sql = format!(
            "SELECT e.id, e.ts_utc_ns, e.ts_precision, e.ts_tz_source, e.ts_flags,
                    e.ts_end_utc_ns, e.source, e.kind,
                    (SELECT key FROM entities WHERE id = e.entity_id),
                    e.pid, e.ppid, e.image, e.user, e.path, e.remote, {log_id_sql},
                    e.summary, e.payload_id IS NOT NULL
             FROM events e
             WHERE {where_sql}
             ORDER BY e.ts_utc_ns, e.id
             LIMIT ? OFFSET ?"
        );

        let mut bound: Vec<Box<dyn ToSql>> = args;
        bound.push(Box::new(limit as i64));
        bound.push(Box::new(offset as i64));
        let refs: Vec<&dyn ToSql> = bound.iter().map(|b| b.as_ref()).collect();

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(refs.as_slice(), |r| {
            let ts = Timestamp {
                utc_ns: r.get(1)?,
                precision: TsPrecision::from_str_lossy(&r.get::<_, String>(2)?),
                tz_source: TzSource::from_str_lossy(&r.get::<_, String>(3)?),
                flags: TsFlags(r.get::<_, i64>(4)? as u32),
            };
            let summary: String = r.get(16)?;
            let log_id = r
                .get::<_, Option<i64>>(15)?
                .map(|v| v as u32)
                .or_else(|| parse_bracket_id(&summary));
            Ok(EventRow {
                id: r.get(0)?,
                iso: ts.to_rfc3339(),
                ts,
                ts_end_utc_ns: r.get(5)?,
                source: r.get(6)?,
                kind: r.get(7)?,
                entity_key: r.get(8)?,
                pid: r.get::<_, Option<i64>>(9)?.map(|v| v as u32),
                ppid: r.get::<_, Option<i64>>(10)?.map(|v| v as u32),
                image: r.get(11)?,
                user: r.get(12)?,
                path: r.get(13)?,
                remote: r.get(14)?,
                log_id,
                summary,
                has_payload: r.get(17)?,
            })
        })?;

        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(FormatError::from)
    }

    /// Count matching events without materializing them, for pagination.
    pub fn count_events(&self, filter: &EventFilter) -> Result<i64> {
        let (where_sql, args) = filter.to_sql(self.has_log_id);
        let refs: Vec<&dyn ToSql> = args.iter().map(|b| b.as_ref()).collect();
        let sql = format!("SELECT COUNT(*) FROM events e WHERE {where_sql}");
        Ok(self
            .conn
            .query_row(&sql, refs.as_slice(), |r| r.get(0))?)
    }

    /// Aggregate matching events into `bins` buckets across a time range.
    ///
    /// This is the zoomed-out timeline. Bucketing in SQL rather than shipping
    /// rows means the wire cost of "show me a year" is the same as "show me a
    /// second": a few hundred integers either way.
    pub fn bin_events(
        &self,
        filter: &EventFilter,
        from_ns: i64,
        to_ns: i64,
        bins: u32,
    ) -> Result<Vec<TimeBin>> {
        let bins = bins.max(1);
        let span = (to_ns - from_ns).max(1);
        // Dividing first keeps the bucket arithmetic inside i64 for spans that
        // would overflow if multiplied by the bin count.
        let width = (span / bins as i64).max(1);

        let mut scoped = filter.clone();
        scoped.from_ns = Some(filter.from_ns.map_or(from_ns, |v| v.max(from_ns)));
        scoped.to_ns = Some(filter.to_ns.map_or(to_ns, |v| v.min(to_ns)));
        let (where_sql, args) = scoped.to_sql(self.has_log_id);

        let sql = format!(
            "SELECT (e.ts_utc_ns - ?) / ? AS bucket, COUNT(*)
             FROM events e
             WHERE {where_sql}
             GROUP BY bucket
             ORDER BY bucket"
        );

        let mut bound: Vec<Box<dyn ToSql>> = vec![Box::new(from_ns), Box::new(width)];
        bound.extend(args);
        let refs: Vec<&dyn ToSql> = bound.iter().map(|b| b.as_ref()).collect();

        let mut stmt = self.conn.prepare(&sql)?;
        let mut counts: HashMap<i64, i64> = HashMap::new();
        for row in stmt.query_map(refs.as_slice(), |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        })? {
            let (bucket, n) = row?;
            counts.insert(bucket.clamp(0, bins as i64 - 1), n);
        }

        Ok((0..bins)
            .map(|i| {
                let start = from_ns + width * i as i64;
                TimeBin {
                    index: i,
                    start_ns: start,
                    end_ns: start + width,
                    count: counts.get(&(i as i64)).copied().unwrap_or(0),
                }
            })
            .collect())
    }

    /// Stacked timeline: one density series per forensic lane, so a 4688 is not
    /// drowned by module-load noise in a single histogram.
    pub fn bin_lanes(
        &self,
        filter: &EventFilter,
        from_ns: i64,
        to_ns: i64,
        bins: u32,
    ) -> Result<Vec<LaneSeries>> {
        let bins = bins.max(1);
        let span = (to_ns - from_ns).max(1);
        let width = (span / bins as i64).max(1);

        let mut scoped = filter.clone();
        scoped.from_ns = Some(filter.from_ns.map_or(from_ns, |v| v.max(from_ns)));
        scoped.to_ns = Some(filter.to_ns.map_or(to_ns, |v| v.min(to_ns)));
        if scoped.exclude_kinds.is_empty() && scoped.kinds.is_empty() {
            scoped.exclude_kinds = vec![EventKind::ModuleLoad, EventKind::ProcessSnapshot];
        }
        let (where_sql, args) = scoped.to_sql(self.has_log_id);

        let sql = format!(
            "SELECT CASE e.kind
                    WHEN 'process_start' THEN 'start'
                    WHEN 'process_end' THEN 'exit'
                    WHEN 'execution_evidence' THEN 'exec'
                    WHEN 'logon_session' THEN 'logon'
                    WHEN 'service_install' THEN 'svc'
                    WHEN 'service_state' THEN 'svc'
                    WHEN 'task_register' THEN 'task'
                    WHEN 'net_connection' THEN 'net'
                    WHEN 'net_listen' THEN 'net'
                    WHEN 'log_record' THEN 'evtx'
                    ELSE 'other'
                  END AS lane,
                  (e.ts_utc_ns - ?) / ? AS bucket,
                  COUNT(*)
             FROM events e
             WHERE {where_sql}
             GROUP BY lane, bucket"
        );

        let mut bound: Vec<Box<dyn ToSql>> = vec![Box::new(from_ns), Box::new(width)];
        bound.extend(args);
        let refs: Vec<&dyn ToSql> = bound.iter().map(|b| b.as_ref()).collect();

        let mut stmt = self.conn.prepare(&sql)?;
        let mut by_lane: HashMap<String, HashMap<i64, i64>> = HashMap::new();
        for row in stmt.query_map(refs.as_slice(), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))
        })? {
            let (lane, bucket, n) = row?;
            by_lane
                .entry(lane)
                .or_default()
                .insert(bucket.clamp(0, bins as i64 - 1), n);
        }

        const ORDER: &[&str] = &["start", "exit", "exec", "logon", "svc", "task", "net", "evtx", "other"];
        Ok(ORDER
            .iter()
            .filter_map(|name| {
                let counts = by_lane.get(*name)?;
                Some(LaneSeries {
                    lane: (*name).to_string(),
                    bins: (0..bins)
                        .map(|i| {
                            let start = from_ns + width * i as i64;
                            TimeBin {
                                index: i,
                                start_ns: start,
                                end_ns: start + width,
                                count: counts.get(&(i as i64)).copied().unwrap_or(0),
                            }
                        })
                        .collect(),
                })
            })
            .filter(|s| s.bins.iter().any(|b| b.count > 0))
            .collect())
    }

    /// Build the process forest.
    ///
    /// Identity is a `process_instance` ULID, not a PID: Windows recycles PIDs,
    /// and a PPID that names a process which had already exited is not a parent.
    /// Impossible edges are dropped; those children surface as annotated roots.
    pub fn process_tree(&self) -> Result<Vec<ProcessNode>> {
        let tol = crate::forest::match_tolerance(&self.conn);
        let forest = crate::forest::load_or_build(&self.conn, tol)?;
        crate::forest::materialize(&self.conn, &forest)
    }

    pub(crate) fn process_forest(&self) -> Result<tpv_model::Forest> {
        let tol = crate::forest::match_tolerance(&self.conn);
        crate::forest::load_or_build(&self.conn, tol)
    }

    /// Fetch a single event by id, for the inspector.
    pub fn event(&self, id: i64) -> Result<Option<EventRow>> {
        Ok(self
            .events(
                &EventFilter {
                    event_ids: vec![id],
                    ..Default::default()
                },
                1,
                0,
            )?
            .pop())
    }

    /// Look up one entity by natural key.
    pub fn entity(&self, key: &str) -> Result<Option<EntityRow>> {
        self.conn
            .query_row(
                "SELECT en.id, en.kind, en.key, en.label, en.attrs,
                        (SELECT MIN(ev.ts_utc_ns) FROM events ev
                          WHERE ev.entity_id = en.id AND ev.ts_flags & 3 = 0),
                        (SELECT COUNT(*) FROM events ev WHERE ev.entity_id = en.id)
                 FROM entities en WHERE en.key = ?1",
                params![key],
                entity_row,
            )
            .optional()?
            .transpose()
    }

    /// Entities one edge away, in either direction.
    ///
    /// The inspector needs both directions because the interesting relations are
    /// asymmetric: a process points at the image it executed, but a service
    /// points at the process hosting it, and an analyst inspecting the process
    /// wants to see the service either way.
    pub fn related(&self, key: &str, limit: u32) -> Result<Vec<RelatedEntity>> {
        let mut out = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT ed.kind, other.id, other.kind, other.key, other.label, other.attrs,
                    (SELECT MIN(ev.ts_utc_ns) FROM events ev
                      WHERE ev.entity_id = other.id AND ev.ts_flags & 3 = 0),
                    (SELECT COUNT(*) FROM events ev WHERE ev.entity_id = other.id),
                    ed.from_id = self.id AS outgoing
             FROM edges ed
             JOIN entities self  ON self.id  IN (ed.from_id, ed.to_id)
             JOIN entities other ON other.id = CASE WHEN ed.from_id = self.id
                                                    THEN ed.to_id ELSE ed.from_id END
             WHERE self.key = ?1
             ORDER BY ed.kind, other.label
             LIMIT ?2",
        )?;
        for row in stmt.query_map(params![key, limit as i64], |r| {
            Ok((
                r.get::<_, String>(0)?,
                entity_row_offset(r, 1)?,
                r.get::<_, i64>(8)? != 0,
            ))
        })? {
            let (kind, entity, outgoing) = row?;
            out.push(RelatedEntity {
                kind,
                entity: entity?,
                outgoing,
            });
        }
        Ok(out)
    }

    /// Distinct sources present in the case, with counts, to populate filter UI.
    ///
    /// Derived from the data rather than from the enum so the list reflects what
    /// this case actually contains: offering a filter for an artifact that was
    /// never collected invites the analyst to conclude it was absent.
    pub fn source_counts(&self) -> Result<Vec<(String, i64)>> {
        self.group_counts("source")
    }

    pub fn kind_counts(&self) -> Result<Vec<(String, i64)>> {
        self.group_counts("kind")
    }

    fn group_counts(&self, column: &str) -> Result<Vec<(String, i64)>> {
        // `column` is a literal chosen by the two callers above, never analyst
        // input, so the format is safe here where a filter value would not be.
        let sql =
            format!("SELECT {column}, COUNT(*) FROM events GROUP BY {column} ORDER BY 2 DESC");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(FormatError::from)
    }

    /// Decompress an event's full source detail.
    pub fn payload(&self, event_id: i64) -> Result<Option<serde_json::Value>> {
        let z: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT p.z FROM events e JOIN payloads p ON p.id = e.payload_id WHERE e.id = ?1",
                params![event_id],
                |r| r.get(0),
            )
            .optional()?;
        match z {
            Some(z) => Ok(Some(serde_json::from_slice(&zstd::decode_all(&z[..])?)?)),
            None => Ok(None),
        }
    }

    pub fn manifest(&self) -> Result<Vec<ManifestEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT source_path, method, size_bytes, sha256,
                    started_utc_ns, finished_utc_ns, events_emitted, error
             FROM manifest ORDER BY started_utc_ns, id",
        )?;
        let rows = stmt.query_map([], |r| {
            let method = r.get::<_, String>(1)?;
            Ok(ManifestEntry {
                source_path: r.get(0)?,
                method: AccessMethod::from_str_lossy(&method).unwrap_or(AccessMethod::Derived),
                size_bytes: r.get::<_, i64>(2)? as u64,
                sha256: r.get(3)?,
                started: bare_ts(r.get(4)?),
                finished: bare_ts(r.get(5)?),
                events_emitted: r.get::<_, i64>(6)? as u64,
                error: r.get(7)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(FormatError::from)
    }

    pub fn blobs(&self) -> Result<Vec<BlobInfo>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, kind, raw_len, sha256, chunk_size, chunk_count FROM blobs ORDER BY name")?;
        let rows = stmt.query_map([], |r| {
            Ok(BlobInfo {
                id: r.get(0)?,
                name: r.get(1)?,
                kind: r.get(2)?,
                raw_len: r.get::<_, i64>(3)? as u64,
                sha256: r.get(4)?,
                chunk_size: r.get::<_, i64>(5)? as u64,
                chunk_count: r.get::<_, i64>(6)? as u64,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(FormatError::from)
    }

    pub fn blob_reader(&self, blob_id: i64) -> Result<BlobReader<'_>> {
        let info = self
            .blobs()?
            .into_iter()
            .find(|b| b.id == blob_id)
            .ok_or(FormatError::BlobNotFound(blob_id))?;
        Ok(BlobReader::new(&self.conn, info))
    }

    pub fn findings(&self) -> Result<Vec<Finding>> {
        let mut stmt = self.conn.prepare(
            "SELECT f.id, f.rule, f.severity, f.confidence, f.title, f.detail,
                    (SELECT key FROM entities WHERE id = f.entity_id)
             FROM findings f
             ORDER BY CASE f.severity
                        WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                      f.rule, f.id",
        )?;

        let raw: Vec<(i64, Finding)> = stmt
            .query_map([], |r| {
                let id: i64 = r.get(0)?;
                Ok((
                    id,
                    Finding {
                        rule: r.get(1)?,
                        severity: Severity::from_str_lossy(&r.get::<_, String>(2)?)
                            .unwrap_or(Severity::Info),
                        confidence: Confidence::from_str_lossy(&r.get::<_, String>(3)?)
                            .unwrap_or(Confidence::Low),
                        title: r.get(4)?,
                        detail: r.get(5)?,
                        evidence: Vec::new(),
                        entity_key: r.get(6)?,
                    },
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut stmt = self
            .conn
            .prepare("SELECT event_id FROM finding_evidence WHERE finding_id = ?1 ORDER BY event_id")?;
        raw.into_iter()
            .map(|(id, mut f)| {
                f.evidence = stmt
                    .query_map(params![id], |r| r.get::<_, i64>(0))?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                Ok(f)
            })
            .collect()
    }

    /// Run the local rule pack and replace the findings table.
    ///
    /// Requires [`Self::open_for_findings`]. Safe to call on every open: the
    /// table is derived, not evidence, and is excluded from the content digest.
    pub fn regenerate_findings(&mut self) -> Result<usize> {
        let findings = crate::findings::scan(self)?;
        let generated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        let n = findings.len();
        self.replace_findings(&findings, generated)?;
        Ok(n)
    }

    /// Replace the derived findings wholesale.
    ///
    /// Wholesale rather than incremental so a rule change can never leave stale
    /// findings behind, and so the operation is a single transaction that either
    /// happens or does not. Requires [`Self::open_for_findings`].
    pub fn replace_findings(&mut self, findings: &[Finding], generated_utc_ns: i64) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM finding_evidence", [])?;
        tx.execute("DELETE FROM findings", [])?;

        for f in findings {
            let entity_id: Option<i64> = match &f.entity_key {
                Some(k) => tx
                    .query_row("SELECT id FROM entities WHERE key = ?1", params![k], |r| {
                        r.get(0)
                    })
                    .optional()?,
                None => None,
            };
            tx.execute(
                "INSERT INTO findings(rule, severity, confidence, title, detail, entity_id, generated_utc_ns)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    f.rule,
                    f.severity.as_str(),
                    f.confidence.as_str(),
                    f.title,
                    f.detail,
                    entity_id,
                    generated_utc_ns
                ],
            )?;
            let fid = tx.last_insert_rowid();
            for ev in &f.evidence {
                tx.execute(
                    "INSERT OR IGNORE INTO finding_evidence(finding_id, event_id) VALUES (?1, ?2)",
                    params![fid, ev],
                )?;
            }
        }

        tx.commit()?;
        Ok(())
    }

    /// Recompute the content digest and compare it with the sealed value.
    ///
    /// Answers "is this the same evidence it was when collected" without needing
    /// the sidecar file, and survives a byte-level rewrite of the database that
    /// preserves its contents.
    pub fn verify_content_digest(&self) -> Result<bool> {
        let Some(sealed) = self.meta_str(schema::META_CONTENT_DIGEST)? else {
            return Ok(false);
        };
        Ok(self.compute_content_digest()? == sealed)
    }

    fn compute_content_digest(&self) -> Result<String> {
        let mut lines = Vec::new();
        for table in ["events", "entities", "edges", "payloads", "blobs", "manifest"] {
            let n: i64 =
                self.conn
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?;
            lines.push(format!("count:{table}={n}"));
        }
        let mut stmt = self.conn.prepare(
            "SELECT source_path, COALESCE(sha256, '-') FROM manifest ORDER BY source_path, id",
        )?;
        for row in stmt.query_map([], |r| {
            Ok(format!(
                "artifact:{}={}",
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?
            ))
        })? {
            lines.push(row?);
        }
        let mut stmt = self
            .conn
            .prepare("SELECT name, sha256, raw_len FROM blobs ORDER BY name")?;
        for row in stmt.query_map([], |r| {
            Ok(format!(
                "blob:{}={}:{}",
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?
            ))
        })? {
            lines.push(row?);
        }
        Ok(crate::hash::sha256_hex(lines.join("\n").as_bytes()))
    }
}

/// Decode an entity starting at column 0.
///
/// Attribute decompression is fallible on a corrupt case, and that must not take
/// the whole query down: the row is still worth showing without its attributes.
/// The outer `rusqlite::Result` is therefore separate from the inner one.
fn entity_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Result<EntityRow>> {
    entity_row_offset(r, 0)
}

fn entity_row_offset(
    r: &rusqlite::Row<'_>,
    base: usize,
) -> rusqlite::Result<Result<EntityRow>> {
    let attrs: Option<Vec<u8>> = r.get(base + 4)?;
    let row = EntityRow {
        id: r.get(base)?,
        kind: r.get(base + 1)?,
        key: r.get(base + 2)?,
        label: r.get(base + 3)?,
        first_seen_ns: r.get(base + 5)?,
        event_count: r.get(base + 6)?,
        attrs: None,
    };
    Ok(match attrs {
        Some(z) => (|| -> Result<EntityRow> {
            let json = zstd::decode_all(&z[..])?;
            Ok(EntityRow {
                attrs: Some(serde_json::from_slice(&json)?),
                ..row
            })
        })(),
        None => Ok(row),
    })
}

fn bare_ts(ns: i64) -> Timestamp {
    Timestamp::new(ns, TsPrecision::Nanosecond, TzSource::NativeUtc)
}
