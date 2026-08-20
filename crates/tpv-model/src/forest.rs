//! Process-instance identity and parent-edge validation.
//!
//! A PID is not an identity. Windows recycles them; a 72-hour case will see the
//! same number worn by unrelated processes. The forest therefore resolves every
//! observation to a [`ProcessInstance`] with a deterministic ULID, then classifies
//! every claimed parent edge so a recycled PID cannot draw `evil.exe` under an
//! innocent parent.
//!
//! Pure over its inputs: the same observations produce the same graph. The
//! `.tpv` writer runs this at finalize; the reader can re-run it from events.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::entity::normalize_path;

/// ±2 s. 4688, Prefetch and the live snapshot stamp time at different grains.
pub const DEFAULT_MATCH_TOLERANCE_NS: i64 = 2_000_000_000;

/// Where a process field was observed. Confidence is a function of this, never
/// a free parameter: PEB is writable by the process, 4688 is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldSource {
    LiveApi,
    Evtx4688,
    Evtx4689,
    Sysmon1,
    Sysmon5,
    MemEprocess,
    MemPeb,
    Prefetch,
    Amcache,
}

impl FieldSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            FieldSource::LiveApi => "live_api",
            FieldSource::Evtx4688 => "evtx_4688",
            FieldSource::Evtx4689 => "evtx_4689",
            FieldSource::Sysmon1 => "sysmon_1",
            FieldSource::Sysmon5 => "sysmon_5",
            FieldSource::MemEprocess => "mem_eprocess",
            FieldSource::MemPeb => "mem_peb",
            FieldSource::Prefetch => "prefetch",
            FieldSource::Amcache => "amcache",
        }
    }

    /// Kernel-emitted and immutable after the fact, pool structure, or neither.
    pub const fn confidence(self) -> FieldConfidence {
        match self {
            FieldSource::Evtx4688
            | FieldSource::Evtx4689
            | FieldSource::Sysmon1
            | FieldSource::Sysmon5
            | FieldSource::MemEprocess => FieldConfidence::Kernel,
            FieldSource::MemPeb => FieldConfidence::UserWritable,
            FieldSource::LiveApi | FieldSource::Prefetch | FieldSource::Amcache => {
                FieldConfidence::Derived
            }
        }
    }

    pub const fn layer(self) -> SourceLayer {
        match self {
            FieldSource::Evtx4688
            | FieldSource::Evtx4689
            | FieldSource::Sysmon1
            | FieldSource::Sysmon5 => SourceLayer::Evtx,
            FieldSource::LiveApi => SourceLayer::Live,
            FieldSource::MemEprocess | FieldSource::MemPeb => SourceLayer::Memory,
            FieldSource::Prefetch | FieldSource::Amcache => SourceLayer::Prefetch,
        }
    }

    pub const fn is_kernel_birth(self) -> bool {
        matches!(self, FieldSource::Evtx4688 | FieldSource::Sysmon1)
    }

    pub const fn is_exit(self) -> bool {
        matches!(self, FieldSource::Evtx4689 | FieldSource::Sysmon5)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldConfidence {
    Kernel,
    Derived,
    UserWritable,
}

impl FieldConfidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            FieldConfidence::Kernel => "kernel",
            FieldConfidence::Derived => "derived",
            FieldConfidence::UserWritable => "user_writable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceLayer {
    Evtx,
    Live,
    Memory,
    Prefetch,
}

impl SourceLayer {
    pub const fn as_str(self) -> &'static str {
        match self {
            SourceLayer::Evtx => "evtx",
            SourceLayer::Live => "live",
            SourceLayer::Memory => "memory",
            SourceLayer::Prefetch => "prefetch",
        }
    }
}

/// What an observation is doing to the instance it refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObservationRole {
    /// Process creation (4688 / Sysmon 1). Seeds an instance.
    Birth,
    /// Live or memory snapshot of a running (or still-allocated) process.
    Snapshot,
    /// Process exit (4689 / Sysmon 5). Closes an instance.
    Exit,
    /// Prefetch / Amcache: execution evidence, attached rather than seeded
    /// unless it matches an existing instance.
    Execution,
}

/// One sighting of a process, from any source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub event_id: Option<i64>,
    pub pid: u32,
    pub ppid: Option<u32>,
    pub at_ns: i64,
    pub image_path: Option<String>,
    pub command_line: Option<String>,
    pub user: Option<String>,
    pub source: FieldSource,
    pub role: ObservationRole,
    /// Present when the collector already created a process entity.
    pub entity_key: Option<String>,
    /// Memory pool-only: present in `_EPROCESS` scan, absent from the live list.
    pub unlinked: bool,
    /// False when `at_ns` is an observation time, not a creation time.
    pub start_exact: bool,
}

/// A parent named by something other than a PPID on an observation (the live
/// snapshot writes `parent_of` edges even when the event row omitted PPID).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentClaim {
    pub parent_entity_key: String,
    pub child_entity_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeState {
    /// Parent identified and alive at the child's start.
    Confirmed,
    /// PPID matches an instance whose start/exit is unknown.
    Inferred,
    /// PPID matches, but that parent had already exited. Recycled PID; do not
    /// draw the edge.
    Impossible,
    /// PPID matches nothing in the case.
    Orphaned,
}

impl EdgeState {
    pub const fn as_str(self) -> &'static str {
        match self {
            EdgeState::Confirmed => "confirmed",
            EdgeState::Inferred => "inferred",
            EdgeState::Impossible => "impossible",
            EdgeState::Orphaned => "orphaned",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessField {
    pub field: String,
    pub value: String,
    pub source: FieldSource,
    pub confidence: FieldConfidence,
    pub observed_utc_ns: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInstance {
    pub id: String,
    pub pid: u32,
    pub start_utc_ns: Option<i64>,
    pub exit_utc_ns: Option<i64>,
    pub image_path: Option<String>,
    pub user: Option<String>,
    pub parent_edge: EdgeState,
    pub claimed_ppid: Option<u32>,
    pub parent_id: Option<String>,
    pub source_set: BTreeSet<SourceLayer>,
    pub fields: Vec<ProcessField>,
    pub event_ids: Vec<i64>,
    pub entity_keys: BTreeSet<String>,
    pub unlinked: bool,
    pub indicators: Vec<String>,
    pub start_exact: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ForestStats {
    pub confirmed: u32,
    pub inferred: u32,
    pub orphaned: u32,
    pub impossible: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forest {
    pub instances: Vec<ProcessInstance>,
    pub stats: ForestStats,
    pub match_tolerance_ns: i64,
}

/// Fuse observations into instances and classify every parent edge.
///
/// Order: seed births, close with exits, merge snapshots, attach prefetch,
/// then validate edges. Prefetch does not create an instance of its own.
pub fn reconcile(
    observations: &[Observation],
    parent_claims: &[ParentClaim],
    match_tolerance_ns: i64,
) -> Forest {
    let tol = match_tolerance_ns.max(0);
    let mut instances: Vec<Working> = Vec::new();

    let mut births: Vec<&Observation> = observations
        .iter()
        .filter(|o| o.role == ObservationRole::Birth)
        .collect();
    births.sort_by_key(|o| (o.pid, o.at_ns, o.event_id));
    for o in births {
        merge_or_seed(&mut instances, o, tol);
    }

    let mut snaps: Vec<&Observation> = observations
        .iter()
        .filter(|o| o.role == ObservationRole::Snapshot)
        .collect();
    snaps.sort_by_key(|o| (o.pid, o.at_ns, o.event_id));
    for o in snaps {
        merge_or_seed(&mut instances, o, tol);
    }

    let mut exits: Vec<&Observation> = observations
        .iter()
        .filter(|o| o.role == ObservationRole::Exit)
        .collect();
    exits.sort_by_key(|o| (o.pid, o.at_ns, o.event_id));
    for o in exits {
        if let Some(idx) = find_open_for_exit(&instances, o, tol) {
            apply_obs(&mut instances[idx], o);
        }
    }

    for o in observations.iter().filter(|o| o.role == ObservationRole::Execution) {
        if let Some(idx) = find_match(&instances, o, tol) {
            apply_obs(&mut instances[idx], o);
        }
    }

    for w in &mut instances {
        w.id = instance_id(w.pid, w.start_utc_ns, w.image_path.as_deref().unwrap_or(""));
        w.indicators = indicators_for(w);
    }

    assign_edges(&mut instances, parent_claims, tol);

    let mut stats = ForestStats::default();
    for w in &instances {
        match w.parent_edge {
            EdgeState::Confirmed => stats.confirmed += 1,
            EdgeState::Inferred => stats.inferred += 1,
            EdgeState::Orphaned => stats.orphaned += 1,
            EdgeState::Impossible => stats.impossible += 1,
        }
    }

    instances.sort_by_key(|w| (w.start_utc_ns.unwrap_or(i64::MAX), w.pid, w.id.clone()));

    Forest {
        instances: instances.into_iter().map(Working::into_instance).collect(),
        stats,
        match_tolerance_ns: tol,
    }
}

struct Working {
    id: String,
    pid: u32,
    start_utc_ns: Option<i64>,
    exit_utc_ns: Option<i64>,
    image_path: Option<String>,
    user: Option<String>,
    claimed_ppid: Option<u32>,
    ppid_kernel: bool,
    source_set: BTreeSet<SourceLayer>,
    fields: Vec<ProcessField>,
    event_ids: Vec<i64>,
    entity_keys: BTreeSet<String>,
    unlinked: bool,
    indicators: Vec<String>,
    parent_edge: EdgeState,
    parent_id: Option<String>,
    start_exact: bool,
}

impl Working {
    fn into_instance(self) -> ProcessInstance {
        ProcessInstance {
            id: self.id,
            pid: self.pid,
            start_utc_ns: self.start_utc_ns,
            exit_utc_ns: self.exit_utc_ns,
            image_path: self.image_path,
            user: self.user,
            parent_edge: self.parent_edge,
            claimed_ppid: self.claimed_ppid,
            parent_id: self.parent_id,
            source_set: self.source_set,
            fields: self.fields,
            event_ids: self.event_ids,
            entity_keys: self.entity_keys,
            unlinked: self.unlinked,
            indicators: self.indicators,
            start_exact: self.start_exact,
        }
    }
}

fn merge_or_seed(instances: &mut Vec<Working>, o: &Observation, tol: i64) {
    if let Some(idx) = find_match(instances, o, tol) {
        apply_obs(&mut instances[idx], o);
    } else {
        instances.push(seed(o));
    }
}

fn seed(o: &Observation) -> Working {
    let mut w = Working {
        id: String::new(),
        pid: o.pid,
        start_utc_ns: match o.role {
            ObservationRole::Birth | ObservationRole::Snapshot => Some(o.at_ns),
            ObservationRole::Exit | ObservationRole::Execution => None,
        },
        exit_utc_ns: if o.role == ObservationRole::Exit {
            Some(o.at_ns)
        } else {
            None
        },
        image_path: o.image_path.clone(),
        user: o.user.clone(),
        claimed_ppid: o.ppid.filter(|p| *p != o.pid),
        ppid_kernel: o.source.is_kernel_birth() && o.ppid.is_some(),
        source_set: BTreeSet::new(),
        fields: Vec::new(),
        event_ids: Vec::new(),
        entity_keys: BTreeSet::new(),
        unlinked: o.unlinked,
        indicators: Vec::new(),
        parent_edge: EdgeState::Orphaned,
        parent_id: None,
        start_exact: o.start_exact && o.role != ObservationRole::Exit,
    };
    apply_obs(&mut w, o);
    w
}

fn apply_obs(w: &mut Working, o: &Observation) {
    w.source_set.insert(o.source.layer());
    if let Some(id) = o.event_id {
        if !w.event_ids.contains(&id) {
            w.event_ids.push(id);
        }
    }
    if let Some(k) = &o.entity_key {
        w.entity_keys.insert(k.clone());
    }
    w.unlinked |= o.unlinked;
    if o.start_exact && o.role == ObservationRole::Birth {
        w.start_exact = true;
    }

    if o.role == ObservationRole::Birth {
        match w.start_utc_ns {
            None => w.start_utc_ns = Some(o.at_ns),
            Some(s) if o.source.is_kernel_birth() && o.at_ns < s => w.start_utc_ns = Some(o.at_ns),
            _ => {}
        }
    }
    if o.role == ObservationRole::Exit {
        w.exit_utc_ns = Some(match w.exit_utc_ns {
            Some(e) => e.max(o.at_ns),
            None => o.at_ns,
        });
    }
    if w.image_path.as_deref().unwrap_or("").is_empty() {
        if let Some(p) = &o.image_path {
            if !p.is_empty() {
                w.image_path = Some(p.clone());
            }
        }
    }
    if w.user.as_deref().unwrap_or("").is_empty() {
        if let Some(u) = &o.user {
            if !u.is_empty() {
                w.user = Some(u.clone());
            }
        }
    }
    if let Some(ppid) = o.ppid.filter(|p| *p != o.pid) {
        if o.source.is_kernel_birth() || !w.ppid_kernel {
            w.claimed_ppid = Some(ppid);
            w.ppid_kernel = o.source.is_kernel_birth();
        }
    }

    push_field(w, "image_path", o.image_path.as_deref(), o);
    // Memory command lines come from the PEB, which the process can overwrite.
    let cmd_source = if o.source == FieldSource::MemEprocess {
        FieldSource::MemPeb
    } else {
        o.source
    };
    let mut cmd_obs = o.clone();
    cmd_obs.source = cmd_source;
    push_field(w, "command_line", o.command_line.as_deref(), &cmd_obs);
    push_field(w, "user_sid", o.user.as_deref(), o);
}

fn push_field(w: &mut Working, field: &str, value: Option<&str>, o: &Observation) {
    let Some(value) = value.map(str::trim).filter(|s| !s.is_empty()) else {
        return;
    };
    if w.fields
        .iter()
        .any(|f| f.field == field && f.source == o.source)
    {
        return;
    }
    w.fields.push(ProcessField {
        field: field.to_string(),
        value: value.to_string(),
        source: o.source,
        confidence: o.source.confidence(),
        observed_utc_ns: o.at_ns,
    });
}

fn images_compatible(a: Option<&str>, b: Option<&str>) -> bool {
    match (norm_image(a), norm_image(b)) {
        (None, _) | (_, None) => true,
        (Some(x), Some(y)) => x == y,
    }
}

fn norm_image(p: Option<&str>) -> Option<String> {
    p.map(str::trim).filter(|s| !s.is_empty()).map(normalize_path)
}

fn find_match(instances: &[Working], o: &Observation, tol: i64) -> Option<usize> {
    let mut best: Option<(i64, usize)> = None;
    for (i, w) in instances.iter().enumerate() {
        if w.pid != o.pid {
            continue;
        }
        if !images_compatible(w.image_path.as_deref(), o.image_path.as_deref()) {
            continue;
        }
        let Some(start) = w.start_utc_ns else {
            if o.role == ObservationRole::Snapshot || o.role == ObservationRole::Birth {
                continue;
            }
            best = Some((i64::MAX, i));
            continue;
        };
        let delta = (o.at_ns - start).abs();
        // Births and snapshots of a recycled PID must not collapse across the
        // tolerance window. Exits and prefetch may land later in the lifetime.
        let within = match o.role {
            ObservationRole::Birth | ObservationRole::Snapshot => delta <= tol,
            ObservationRole::Exit | ObservationRole::Execution => {
                o.at_ns + tol >= start && w.exit_utc_ns.map(|e| o.at_ns <= e + tol).unwrap_or(true)
            }
        };
        if !within {
            continue;
        }
        if best.map(|(d, _)| delta < d).unwrap_or(true) {
            best = Some((delta, i));
        }
    }
    best.map(|(_, i)| i)
}

fn find_open_for_exit(instances: &[Working], o: &Observation, tol: i64) -> Option<usize> {
    let mut best: Option<(i64, usize)> = None;
    for (i, w) in instances.iter().enumerate() {
        if w.pid != o.pid {
            continue;
        }
        if !images_compatible(w.image_path.as_deref(), o.image_path.as_deref()) {
            continue;
        }
        let start = w.start_utc_ns.unwrap_or(i64::MIN);
        if o.at_ns + tol < start {
            continue;
        }
        if w.exit_utc_ns.is_some() {
            continue;
        }
        let dist = o.at_ns.saturating_sub(start);
        if best.map(|(d, _)| dist < d).unwrap_or(true) {
            best = Some((dist, i));
        }
    }
    best.map(|(_, i)| i)
}

fn assign_edges(instances: &mut [Working], claims: &[ParentClaim], _tol: i64) {
    let by_entity: HashMap<String, String> = instances
        .iter()
        .flat_map(|w| w.entity_keys.iter().map(|k| (k.clone(), w.id.clone())))
        .collect();

    let by_id: HashMap<String, (u32, Option<i64>, Option<i64>)> = instances
        .iter()
        .map(|w| (w.id.clone(), (w.pid, w.start_utc_ns, w.exit_utc_ns)))
        .collect();

    // Extra PPID claims from parent_of edges, used when the observation had none.
    let mut claimed_parent_id: HashMap<String, String> = HashMap::new();
    for c in claims {
        if let (Some(p), Some(ch)) = (by_entity.get(&c.parent_entity_key), by_entity.get(&c.child_entity_key))
        {
            claimed_parent_id.entry(ch.clone()).or_insert_with(|| p.clone());
        }
    }

    let snapshot: Vec<(String, u32, Option<i64>, Option<i64>, Option<u32>)> = instances
        .iter()
        .map(|w| {
            (
                w.id.clone(),
                w.pid,
                w.start_utc_ns,
                w.exit_utc_ns,
                w.claimed_ppid,
            )
        })
        .collect();

    for w in instances.iter_mut() {
        let child_start = w.start_utc_ns;
        let mut parent_id = w.claimed_ppid.and_then(|ppid| {
            resolve_parent(&snapshot, &w.id, ppid, child_start)
        });
        if parent_id.is_none() {
            parent_id = claimed_parent_id.get(&w.id).cloned();
        }

        let Some(pid_parent) = parent_id else {
            if w.claimed_ppid.is_none() && !claimed_parent_id.contains_key(&w.id) {
                // No PPID was ever claimed (System, or a stub). Treat as a real
                // root rather than an orphan of a missing parent.
                w.parent_edge = EdgeState::Orphaned;
                if w.pid == 0 || w.pid == 4 {
                    w.parent_edge = EdgeState::Confirmed;
                    w.parent_id = None;
                }
            } else {
                w.parent_edge = EdgeState::Orphaned;
            }
            continue;
        };

        let Some(&(ppid, p_start, p_exit)) = by_id.get(&pid_parent) else {
            w.parent_edge = EdgeState::Orphaned;
            continue;
        };
        let _ = ppid;

        match (child_start, p_start, p_exit) {
            (Some(c), Some(ps), Some(pe)) if c < ps || c > pe => {
                w.parent_edge = EdgeState::Impossible;
                w.parent_id = None;
            }
            (Some(c), Some(ps), None) if c < ps => {
                w.parent_edge = EdgeState::Impossible;
                w.parent_id = None;
            }
            (Some(_), Some(_), _) => {
                w.parent_edge = EdgeState::Confirmed;
                w.parent_id = Some(pid_parent);
            }
            _ => {
                w.parent_edge = EdgeState::Inferred;
                w.parent_id = Some(pid_parent);
            }
        }
    }
}

fn resolve_parent(
    snapshot: &[(String, u32, Option<i64>, Option<i64>, Option<u32>)],
    child_id: &str,
    ppid: u32,
    child_start: Option<i64>,
) -> Option<String> {
    let mut candidates: Vec<&(String, u32, Option<i64>, Option<i64>, Option<u32>)> = snapshot
        .iter()
        .filter(|(id, pid, _, _, _)| *pid == ppid && id != child_id)
        .collect();
    if candidates.is_empty() {
        return None;
    }
    if let Some(c) = child_start {
        let covering: Vec<_> = candidates
            .iter()
            .copied()
            .filter(|(_, _, start, exit, _)| {
                let after_start = start.map(|s| s <= c).unwrap_or(true);
                let before_exit = exit.map(|e| c <= e).unwrap_or(true);
                after_start && before_exit
            })
            .collect();
        if covering.len() == 1 {
            return Some(covering[0].0.clone());
        }
        if covering.is_empty() {
            // Every candidate had already died, or had not been born. Recycle.
            return candidates
                .iter()
                .max_by_key(|(_, _, start, _, _)| start.unwrap_or(i64::MIN))
                .map(|c| c.0.clone());
        }
        candidates = covering;
    }
    candidates.sort_by_key(|(_, _, start, _, _)| start.unwrap_or(i64::MAX));
    candidates.last().map(|c| c.0.clone())
}

fn indicators_for(w: &Working) -> Vec<String> {
    let mut out = Vec::new();
    if w.unlinked {
        out.push("PROC_UNLINKED".into());
    }
    if cmdline_mismatch(w) {
        out.push("CMDLINE_PEB_MISMATCH".into());
    }
    if masquerade_path(w.image_path.as_deref()) {
        out.push("MASQUERADE_PATH".into());
    }
    if short_lived_shell(w) {
        out.push("SHORT_LIVED_SHELL".into());
    }
    out
}

fn cmdline_mismatch(w: &Working) -> bool {
    let peb = w
        .fields
        .iter()
        .find(|f| f.field == "command_line" && f.source == FieldSource::MemPeb)
        .map(|f| f.value.as_str());
    let kernel = w
        .fields
        .iter()
        .find(|f| {
            f.field == "command_line"
                && matches!(f.source, FieldSource::Evtx4688 | FieldSource::Sysmon1)
        })
        .map(|f| f.value.as_str());
    match (peb, kernel) {
        (Some(a), Some(b)) => a.trim() != b.trim(),
        _ => false,
    }
}

fn masquerade_path(image: Option<&str>) -> bool {
    let Some(path) = image else {
        return false;
    };
    let n = normalize_path(path);
    let name = n.rsplit('\\').next().unwrap_or(&n);
    const SYSTEM: &[&str] = &[
        "svchost.exe",
        "lsass.exe",
        "services.exe",
        "csrss.exe",
        "smss.exe",
        "winlogon.exe",
        "wininit.exe",
        "conhost.exe",
        "dwm.exe",
        "dllhost.exe",
        "taskhostw.exe",
        "runtimebroker.exe",
    ];
    if name == "explorer.exe" {
        return n != "c:\\windows\\explorer.exe";
    }
    if SYSTEM.contains(&name) {
        return !(n.contains("\\windows\\system32\\") || n.contains("\\windows\\syswow64\\"));
    }
    false
}

fn short_lived_shell(w: &Working) -> bool {
    let Some(path) = w.image_path.as_deref() else {
        return false;
    };
    let name = normalize_path(path);
    let base = name.rsplit('\\').next().unwrap_or(&name);
    if !matches!(base, "cmd.exe" | "powershell.exe" | "pwsh.exe" | "wscript.exe") {
        return false;
    }
    match (w.start_utc_ns, w.exit_utc_ns) {
        (Some(s), Some(e)) if e >= s => e - s < 5_000_000_000,
        _ => false,
    }
}

/// Deterministic ULID: 48-bit start timestamp + 80-bit hash of the natural key.
/// Reimporting the same case yields the same ids.
pub fn instance_id(pid: u32, start_utc_ns: Option<i64>, image: &str) -> String {
    let start = start_utc_ns.unwrap_or(0);
    let ts_ms = if start > 0 {
        (start / 1_000_000) as u64
    } else {
        0
    };
    let mut hasher = Sha256::new();
    hasher.update(pid.to_le_bytes());
    hasher.update(start.to_le_bytes());
    hasher.update(normalize_path(image).as_bytes());
    let digest = hasher.finalize();
    let mut entropy = [0u8; 10];
    entropy.copy_from_slice(&digest[..10]);
    encode_ulid(ts_ms, &entropy)
}

fn encode_ulid(ts_ms: u64, entropy: &[u8; 10]) -> String {
    let mut n: u128 = u128::from(ts_ms & 0xFFFF_FFFF_FFFF) << 80;
    for (i, b) in entropy.iter().enumerate() {
        n |= u128::from(*b) << (8 * (9 - i));
    }
    const A: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut out = [0u8; 26];
    for i in (0..26).rev() {
        out[i] = A[(n & 31) as usize];
        n >>= 5;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Stable natural key still used for entity dedup alongside the ULID.
pub fn entity_key_for(pid: u32, start_utc_ns: Option<i64>) -> String {
    match start_utc_ns {
        Some(ns) if ns != 0 => format!("proc:{pid}:{ns}"),
        _ => format!("proc:{pid}:unknown"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn birth(pid: u32, ppid: u32, at: i64, image: &str) -> Observation {
        Observation {
            event_id: Some(at),
            pid,
            ppid: Some(ppid),
            at_ns: at,
            image_path: Some(image.into()),
            command_line: Some(format!("{image} --start")),
            user: None,
            source: FieldSource::Evtx4688,
            role: ObservationRole::Birth,
            entity_key: None,
            unlinked: false,
            start_exact: true,
        }
    }

    fn exit(pid: u32, at: i64, image: &str) -> Observation {
        Observation {
            event_id: Some(at + 1),
            pid,
            ppid: None,
            at_ns: at,
            image_path: Some(image.into()),
            command_line: None,
            user: None,
            source: FieldSource::Evtx4689,
            role: ObservationRole::Exit,
            entity_key: None,
            unlinked: false,
            start_exact: true,
        }
    }

    fn snap(pid: u32, ppid: u32, at: i64, image: &str) -> Observation {
        Observation {
            event_id: Some(at + 50),
            pid,
            ppid: Some(ppid),
            at_ns: at,
            image_path: Some(image.into()),
            command_line: Some(format!("{image} --live")),
            user: None,
            source: FieldSource::LiveApi,
            role: ObservationRole::Snapshot,
            entity_key: Some(format!("proc:{pid}:{at}")),
            unlinked: false,
            start_exact: true,
        }
    }

    #[test]
    fn recycled_pid_three_times_is_three_instances() {
        let image = r"C:\Windows\System32\cmd.exe";
        let obs = vec![
            birth(4242, 4, 1_000, image),
            exit(4242, 10_000, image),
            birth(4242, 800, 1_000_000_000_000, image),
            exit(4242, 1_000_000_010_000, image),
            birth(4242, 1000, 2_000_000_000_000, image),
        ];
        let forest = reconcile(&obs, &[], DEFAULT_MATCH_TOLERANCE_NS);
        assert_eq!(forest.instances.len(), 3);
        let pids: Vec<_> = forest.instances.iter().map(|i| i.pid).collect();
        assert!(pids.iter().all(|p| *p == 4242));
        let starts: Vec<_> = forest
            .instances
            .iter()
            .map(|i| i.start_utc_ns.unwrap())
            .collect();
        assert_eq!(starts, vec![1_000, 1_000_000_000_000, 2_000_000_000_000]);
    }

    #[test]
    fn same_pid_within_tolerance_collapses() {
        let image = r"C:\Windows\System32\notepad.exe";
        let obs = vec![
            birth(100, 4, 10_000_000_000, image),
            snap(100, 4, 10_000_000_000 + 500_000_000, image),
        ];
        let forest = reconcile(&obs, &[], DEFAULT_MATCH_TOLERANCE_NS);
        assert_eq!(forest.instances.len(), 1);
        assert!(forest.instances[0].source_set.contains(&SourceLayer::Evtx));
        assert!(forest.instances[0].source_set.contains(&SourceLayer::Live));
    }

    #[test]
    fn impossible_edge_is_not_drawn_on_recycle() {
        // Parent pid 800 died, then pid 800 was reused as an innocent host.
        // A child that started while the original parent was alive should
        // still attach; a child whose PPID 800 now names the new process
        // after the original died must not.
        let obs = vec![
            birth(800, 4, 1_000, r"C:\Windows\System32\services.exe"),
            exit(800, 5_000, r"C:\Windows\System32\services.exe"),
            birth(1337, 800, 2_000, r"C:\Users\Public\good.exe"),
            birth(800, 4, 9_000, r"C:\Windows\System32\svchost.exe"),
            // Started after the original pid 800 died and before the recycled
            // one was born: the PPID names a number, not a living parent.
            birth(9999, 800, 6_000, r"C:\Users\Public\evil.exe"),
        ];
        let forest = reconcile(&obs, &[], DEFAULT_MATCH_TOLERANCE_NS);
        let evil = forest
            .instances
            .iter()
            .find(|i| i.pid == 9999)
            .expect("evil");
        assert_eq!(evil.parent_edge, EdgeState::Impossible);
        assert!(evil.parent_id.is_none(), "recycled PPID must not draw an edge");

        let good = forest
            .instances
            .iter()
            .find(|i| i.pid == 1337)
            .expect("good");
        assert_eq!(good.parent_edge, EdgeState::Confirmed);
        assert!(good.parent_id.is_some());
    }

    #[test]
    fn reimport_is_deterministic() {
        let obs = vec![
            birth(4, 0, 1, r"\SystemRoot\System32\ntoskrnl.exe"),
            birth(100, 4, 2, r"C:\Windows\System32\cmd.exe"),
        ];
        let a = reconcile(&obs, &[], DEFAULT_MATCH_TOLERANCE_NS);
        let b = reconcile(&obs, &[], DEFAULT_MATCH_TOLERANCE_NS);
        assert_eq!(a.instances[0].id, b.instances[0].id);
        assert_eq!(a.instances[1].id, b.instances[1].id);
        assert_ne!(a.instances[0].id, a.instances[1].id);
    }

    #[test]
    fn peb_vs_4688_cmdline_mismatch_is_flagged() {
        let mut peb = snap(50, 4, 10_000, r"C:\Windows\System32\cmd.exe");
        peb.source = FieldSource::MemEprocess;
        peb.command_line = Some("cmd.exe /c whoami".into());
        let mut evtx = birth(50, 4, 10_000, r"C:\Windows\System32\cmd.exe");
        evtx.command_line = Some("cmd.exe /c calc.exe".into());
        let forest = reconcile(&[evtx, peb], &[], DEFAULT_MATCH_TOLERANCE_NS);
        assert_eq!(forest.instances.len(), 1);
        assert!(forest.instances[0]
            .indicators
            .iter()
            .any(|i| i == "CMDLINE_PEB_MISMATCH"));
    }

    #[test]
    fn masquerade_svchost_outside_system32() {
        let obs = vec![birth(
            66,
            4,
            1,
            r"C:\Users\Public\svchost.exe",
        )];
        let forest = reconcile(&obs, &[], DEFAULT_MATCH_TOLERANCE_NS);
        assert!(forest.instances[0]
            .indicators
            .iter()
            .any(|i| i == "MASQUERADE_PATH"));
    }

    #[test]
    fn parent_of_claim_fills_missing_ppid() {
        let mut child = snap(200, 200, 2_000, r"C:\Windows\System32\cmd.exe");
        child.ppid = None;
        child.entity_key = Some("proc:200:2000".into());
        let mut parent = snap(4, 4, 1_000, r"\SystemRoot\System32\ntoskrnl.exe");
        parent.ppid = None;
        parent.entity_key = Some("proc:4:1000".into());
        let claims = [ParentClaim {
            parent_entity_key: "proc:4:1000".into(),
            child_entity_key: "proc:200:2000".into(),
        }];
        let forest = reconcile(&[parent, child], &claims, DEFAULT_MATCH_TOLERANCE_NS);
        let cmd = forest.instances.iter().find(|i| i.pid == 200).unwrap();
        assert_eq!(cmd.parent_edge, EdgeState::Confirmed);
        assert!(cmd.parent_id.is_some());
    }
}
