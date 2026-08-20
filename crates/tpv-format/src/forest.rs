//! Load process observations from a case and run the forest engine.
//!
//! Collection writes events and `parent_of` edges. Identity and edge validation
//! happen here, once, as a pure function of those rows — never while drawing.

use rusqlite::{params, Connection, OptionalExtension};
use tpv_model::{
    entity_key_for, reconcile, EdgeState, FieldSource, Forest, Observation, ObservationRole,
    ParentClaim, DEFAULT_MATCH_TOLERANCE_NS,
};

use crate::error::Result;
use crate::reader::{parse_bracket_id, ProcessNode, ProcessStart, RelatedLog};
use crate::schema;
use tpv_model::time::{TsPrecision, TzSource, Timestamp};

/// Rebuild the derived forest tables from events. Called at finalize.
pub fn persist(conn: &Connection, match_tolerance_ns: i64) -> Result<Forest> {
    ensure_tables(conn)?;
    let forest = build(conn, match_tolerance_ns)?;
    write_tables(conn, &forest)?;
    Ok(forest)
}

/// Forest for drawing. Prefers the persisted tables; rebuilds in memory when
/// they are absent so a v0.1 case still gets instance identity.
pub fn load_or_build(conn: &Connection, match_tolerance_ns: i64) -> Result<Forest> {
    if table_exists(conn, "process_instance")? {
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM process_instance", [], |r| r.get(0))?;
        if n > 0 {
            return read_tables(conn);
        }
    }
    build(conn, match_tolerance_ns)
}

pub fn match_tolerance(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT value FROM meta WHERE key = ?1",
        [schema::META_MATCH_TOLERANCE_NS],
        |r| r.get::<_, String>(0),
    )
    .ok()
    .and_then(|s| s.parse().ok())
    .unwrap_or(DEFAULT_MATCH_TOLERANCE_NS)
}

fn build(conn: &Connection, match_tolerance_ns: i64) -> Result<Forest> {
    let observations = observations(conn)?;
    let claims = parent_claims(conn)?;
    Ok(reconcile(&observations, &claims, match_tolerance_ns))
}

fn ensure_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS process_instance (
            id              TEXT PRIMARY KEY,
            pid             INTEGER NOT NULL,
            start_utc_ns    INTEGER,
            exit_utc_ns     INTEGER,
            image_path      TEXT,
            user_sid        TEXT,
            entity_id       INTEGER,
            unlinked        INTEGER NOT NULL DEFAULT 0,
            source_set      TEXT NOT NULL,
            parent_edge     TEXT NOT NULL,
            claimed_ppid    INTEGER,
            parent_id       TEXT,
            indicators      TEXT NOT NULL DEFAULT '[]',
            event_ids       TEXT NOT NULL DEFAULT '[]',
            start_exact     INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_pi_pid_start ON process_instance(pid, start_utc_ns);
        CREATE TABLE IF NOT EXISTS process_field (
            instance_id     TEXT NOT NULL,
            field           TEXT NOT NULL,
            value           TEXT,
            source          TEXT NOT NULL,
            confidence      TEXT NOT NULL,
            observed_utc_ns INTEGER NOT NULL,
            PRIMARY KEY (instance_id, field, source)
        );
        "#,
    )?;
    Ok(())
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [name],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

fn observations(conn: &Connection) -> Result<Vec<Observation>> {
    let has_log_id = column_exists(conn, "events", "log_id")?;
    let log_sql = if has_log_id { "e.log_id" } else { "NULL" };
    let sql = format!(
        "SELECT e.id, e.ts_utc_ns, e.source, e.kind, e.pid, e.ppid, e.image, e.user,
                en.key, e.summary, {log_sql}, p.z, e.ts_flags
         FROM events e
         LEFT JOIN entities en ON en.id = e.entity_id
         LEFT JOIN payloads p ON p.id = e.payload_id
         WHERE e.kind IN ('process_start', 'process_end', 'process_snapshot', 'execution_evidence')
           AND (e.pid IS NOT NULL OR en.kind = 'process')"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut out = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, Option<i64>>(4)?,
            r.get::<_, Option<i64>>(5)?,
            r.get::<_, Option<String>>(6)?,
            r.get::<_, Option<String>>(7)?,
            r.get::<_, Option<String>>(8)?,
            r.get::<_, String>(9)?,
            r.get::<_, Option<i64>>(10)?,
            r.get::<_, Option<Vec<u8>>>(11)?,
            r.get::<_, i64>(12)?,
        ))
    })?;
    for row in rows {
        let (id, ts, source, kind, pid_col, ppid, image, user, entity_key, summary, log_id, payload_z, ts_flags) =
            row?;
        let Some((src, role)) = classify(&source, &kind, log_id) else {
            continue;
        };
        let pid = pid_col
            .map(|p| p as u32)
            .or_else(|| entity_key.as_deref().and_then(pid_from_key));
        let Some(pid) = pid else {
            continue;
        };
        let payload = payload_z
            .and_then(|z| zstd::decode_all(&z[..]).ok())
            .and_then(|j| serde_json::from_slice::<serde_json::Value>(&j).ok());
        let command_line = command_line_from(&payload, &summary, role);
        let unlinked = summary.contains("MISSING from the kernel")
            || payload
                .as_ref()
                .and_then(|p| p.get("discovery"))
                .and_then(|v| v.as_str())
                == Some("unlinked")
            || payload
                .as_ref()
                .and_then(|p| p.get("hidden_from_process_list"))
                .and_then(|v| v.as_bool())
                == Some(true);
        let unknown_key = entity_key
            .as_deref()
            .map(|k| k.ends_with(":unknown"))
            .unwrap_or(false);
        let inferred = ts_flags & 4 != 0;
        let start_exact = match role {
            ObservationRole::Birth => true,
            ObservationRole::Snapshot => !unknown_key && !inferred,
            _ => false,
        };
        if let Some(k) = &entity_key {
            seen_keys.insert(k.clone());
        }
        out.push(Observation {
            event_id: Some(id),
            pid,
            ppid: ppid.map(|p| p as u32),
            at_ns: ts,
            image_path: image,
            command_line,
            user,
            source: src,
            role,
            entity_key,
            unlinked,
            start_exact,
        });
    }
    drop(stmt);
    out.extend(entity_stubs(conn, &seen_keys)?);
    Ok(out)
}

fn pid_from_key(key: &str) -> Option<u32> {
    key.strip_prefix("proc:")?.split(':').next()?.parse().ok()
}

fn entity_stubs(
    conn: &Connection,
    seen: &std::collections::HashSet<String>,
) -> Result<Vec<Observation>> {
    let mut stmt = conn.prepare(
        "SELECT key, label, attrs FROM entities WHERE kind = 'process'",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<Vec<u8>>>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (key, label, attrs_z) = row?;
        if seen.contains(&key) {
            continue;
        }
        let Some(pid) = pid_from_key(&key) else {
            continue;
        };
        let start = key
            .rsplit(':')
            .next()
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|n| *n != 0);
        let attrs = attrs_z
            .and_then(|z| zstd::decode_all(&z[..]).ok())
            .and_then(|j| serde_json::from_slice::<serde_json::Value>(&j).ok());
        let text = |k: &str| {
            attrs
                .as_ref()
                .and_then(|a| a.get(k))
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        };
        out.push(Observation {
            event_id: None,
            pid,
            ppid: None,
            at_ns: start.unwrap_or(0),
            image_path: text("image_path").or(Some(label)),
            command_line: text("command_line").or_else(|| text("cmdline")),
            user: text("user"),
            source: FieldSource::LiveApi,
            role: ObservationRole::Snapshot,
            entity_key: Some(key),
            unlinked: false,
            start_exact: start.is_some(),
        });
    }
    Ok(out)
}

fn classify(source: &str, kind: &str, log_id: Option<i64>) -> Option<(FieldSource, ObservationRole)> {
    match (source, kind, log_id) {
        ("evtx", "process_start", Some(1)) => Some((FieldSource::Sysmon1, ObservationRole::Birth)),
        ("evtx", "process_start", _) => Some((FieldSource::Evtx4688, ObservationRole::Birth)),
        ("evtx", "process_end", Some(5)) => Some((FieldSource::Sysmon5, ObservationRole::Exit)),
        ("evtx", "process_end", _) => Some((FieldSource::Evtx4689, ObservationRole::Exit)),
        ("live", "process_snapshot", _) => Some((FieldSource::LiveApi, ObservationRole::Snapshot)),
        ("memory", "process_snapshot", _) => {
            Some((FieldSource::MemEprocess, ObservationRole::Snapshot))
        }
        ("memory", "process_end", _) => Some((FieldSource::MemEprocess, ObservationRole::Exit)),
        ("prefetch", "execution_evidence", _) => {
            Some((FieldSource::Prefetch, ObservationRole::Execution))
        }
        ("amcache", "execution_evidence", _) => {
            Some((FieldSource::Amcache, ObservationRole::Execution))
        }
        _ => None,
    }
}

fn command_line_from(
    payload: &Option<serde_json::Value>,
    summary: &str,
    role: ObservationRole,
) -> Option<String> {
    if let Some(p) = payload {
        for key in ["command_line", "CommandLine"] {
            if let Some(s) = text_in(p, key) {
                return Some(s);
            }
        }
        if let Some(s) = p
            .get("data")
            .and_then(|d| d.get("CommandLine"))
            .and_then(json_text)
        {
            return Some(s);
        }
    }
    if role == ObservationRole::Birth {
        if let Some((_, rest)) = summary.split_once(" started: ") {
            let s = rest.trim();
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

fn text_in(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key).and_then(json_text)
}

fn json_text(v: &serde_json::Value) -> Option<String> {
    v.as_str()
        .map(str::to_owned)
        .filter(|s| !s.is_empty())
}

fn parent_claims(conn: &Connection) -> Result<Vec<ParentClaim>> {
    let mut stmt = conn.prepare(
        "SELECT p.key, c.key
         FROM edges ed
         JOIN entities p ON p.id = ed.from_id
         JOIN entities c ON c.id = ed.to_id
         WHERE ed.kind = 'parent_of'",
    )?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = Vec::new();
    for row in rows {
        let (parent, child) = row?;
        out.push(ParentClaim {
            parent_entity_key: parent,
            child_entity_key: child,
        });
    }
    Ok(out)
}

fn write_tables(conn: &Connection, forest: &Forest) -> Result<()> {
    conn.execute_batch(
        "UPDATE process_instance SET parent_id = NULL;
         DELETE FROM process_field;
         DELETE FROM process_instance;",
    )?;
    for inst in &forest.instances {
        let entity_id = resolve_entity_id(conn, inst)?;
        let source_set = inst
            .source_set
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let indicators = serde_json::to_string(&inst.indicators).unwrap_or_else(|_| "[]".into());
        conn.execute(
            "INSERT INTO process_instance(
                id, pid, start_utc_ns, exit_utc_ns, image_path, user_sid, entity_id,
                unlinked, source_set, parent_edge, claimed_ppid, parent_id, indicators, event_ids, start_exact
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,NULL,?12,?13,?14)",
            params![
                inst.id,
                inst.pid as i64,
                inst.start_utc_ns,
                inst.exit_utc_ns,
                inst.image_path,
                inst.user,
                entity_id,
                inst.unlinked as i64,
                source_set,
                inst.parent_edge.as_str(),
                inst.claimed_ppid.map(|p| p as i64),
                indicators,
                serde_json::to_string(&inst.event_ids).unwrap_or_else(|_| "[]".into()),
                inst.start_exact as i64,
            ],
        )?;
        for f in &inst.fields {
            conn.execute(
                "INSERT INTO process_field(instance_id, field, value, source, confidence, observed_utc_ns)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    inst.id,
                    f.field,
                    f.value,
                    f.source.as_str(),
                    f.confidence.as_str(),
                    f.observed_utc_ns,
                ],
            )?;
        }
    }
    for inst in &forest.instances {
        if let Some(parent) = &inst.parent_id {
            conn.execute(
                "UPDATE process_instance SET parent_id = ?1 WHERE id = ?2",
                params![parent, inst.id],
            )?;
        }
    }
    Ok(())
}

fn resolve_entity_id(conn: &Connection, inst: &tpv_model::ProcessInstance) -> Result<Option<i64>> {
    for key in &inst.entity_keys {
        if let Some(id) = conn
            .query_row("SELECT id FROM entities WHERE key = ?1", [key], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?
        {
            return Ok(Some(id));
        }
    }
    let key = entity_key_for(inst.pid, inst.start_utc_ns);
    Ok(conn
        .query_row("SELECT id FROM entities WHERE key = ?1", [key], |r| {
            r.get::<_, i64>(0)
        })
        .optional()?)
}

fn read_tables(conn: &Connection) -> Result<Forest> {
    use std::collections::BTreeSet;
    use tpv_model::{FieldConfidence, ProcessField, ProcessInstance, SourceLayer};

    let mut stmt = conn.prepare(
        "SELECT id, pid, start_utc_ns, exit_utc_ns, image_path, user_sid, unlinked,
                source_set, parent_edge, claimed_ppid, parent_id, indicators, event_ids, start_exact
         FROM process_instance",
    )?;
    let mut instances = Vec::new();
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, Option<i64>>(2)?,
            r.get::<_, Option<i64>>(3)?,
            r.get::<_, Option<String>>(4)?,
            r.get::<_, Option<String>>(5)?,
            r.get::<_, i64>(6)?,
            r.get::<_, String>(7)?,
            r.get::<_, String>(8)?,
            r.get::<_, Option<i64>>(9)?,
            r.get::<_, Option<String>>(10)?,
            r.get::<_, String>(11)?,
            r.get::<_, String>(12)?,
            r.get::<_, i64>(13)?,
        ))
    })?;
    for row in rows {
        let (
            id,
            pid,
            start,
            exit,
            image,
            user,
            unlinked,
            source_set,
            parent_edge,
            claimed_ppid,
            parent_id,
            indicators,
            event_ids_json,
            start_exact,
        ) = row?;
        let mut fields_stmt = conn.prepare(
            "SELECT field, value, source, confidence, observed_utc_ns
             FROM process_field WHERE instance_id = ?1",
        )?;
        let mut fields = Vec::new();
        let frows = fields_stmt.query_map([&id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?;
        for f in frows {
            let (field, value, source, confidence, observed) = f?;
            let Some(src) = parse_source(&source) else {
                continue;
            };
            fields.push(ProcessField {
                field,
                value: value.unwrap_or_default(),
                source: src,
                confidence: match confidence.as_str() {
                    "kernel" => FieldConfidence::Kernel,
                    "user_writable" => FieldConfidence::UserWritable,
                    _ => FieldConfidence::Derived,
                },
                observed_utc_ns: observed,
            });
        }
        let source_set: BTreeSet<SourceLayer> = source_set
            .split(',')
            .filter_map(parse_layer)
            .collect();
        let parent_edge = match parent_edge.as_str() {
            "confirmed" => EdgeState::Confirmed,
            "inferred" => EdgeState::Inferred,
            "impossible" => EdgeState::Impossible,
            _ => EdgeState::Orphaned,
        };
        instances.push(ProcessInstance {
            id,
            pid: pid as u32,
            start_utc_ns: start,
            exit_utc_ns: exit,
            image_path: image,
            user,
            parent_edge,
            claimed_ppid: claimed_ppid.map(|p| p as u32),
            parent_id,
            source_set,
            fields,
            event_ids: serde_json::from_str(&event_ids_json).unwrap_or_default(),
            entity_keys: BTreeSet::new(),
            unlinked: unlinked != 0,
            indicators: serde_json::from_str(&indicators).unwrap_or_default(),
            start_exact: start_exact != 0,
        });
    }
    drop(stmt);

    let mut stats = tpv_model::ForestStats::default();
    for i in &instances {
        match i.parent_edge {
            EdgeState::Confirmed => stats.confirmed += 1,
            EdgeState::Inferred => stats.inferred += 1,
            EdgeState::Orphaned => stats.orphaned += 1,
            EdgeState::Impossible => stats.impossible += 1,
        }
    }
    Ok(Forest {
        instances,
        stats,
        match_tolerance_ns: match_tolerance(conn),
    })
}

fn parse_source(s: &str) -> Option<FieldSource> {
    Some(match s {
        "live_api" => FieldSource::LiveApi,
        "evtx_4688" => FieldSource::Evtx4688,
        "evtx_4689" => FieldSource::Evtx4689,
        "sysmon_1" => FieldSource::Sysmon1,
        "sysmon_5" => FieldSource::Sysmon5,
        "mem_eprocess" => FieldSource::MemEprocess,
        "mem_peb" => FieldSource::MemPeb,
        "prefetch" => FieldSource::Prefetch,
        "amcache" => FieldSource::Amcache,
        _ => return None,
    })
}

fn parse_layer(s: &str) -> Option<tpv_model::SourceLayer> {
    Some(match s {
        "evtx" => tpv_model::SourceLayer::Evtx,
        "live" => tpv_model::SourceLayer::Live,
        "memory" => tpv_model::SourceLayer::Memory,
        "prefetch" => tpv_model::SourceLayer::Prefetch,
        _ => return None,
    })
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for name in names {
        if name? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Turn a forest plus entity attributes into the tree the viewer draws.
pub fn materialize(conn: &Connection, forest: &Forest) -> Result<Vec<ProcessNode>> {
    use std::collections::HashMap;

    let attrs = entity_attrs(conn)?;
    let counts = event_counts(conn)?;
    let sev = max_severity(conn)?;

    let mut nodes: HashMap<String, ProcessNode> = HashMap::new();
    for inst in &forest.instances {
        let key = inst
            .entity_keys
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| entity_key_for(inst.pid, inst.start_utc_ns));
        let (entity_id, label, image, command_line, user, elevated, access_error) =
            lookup_attrs(&attrs, inst, &key);
        let image = inst.image_path.clone().or(image);
        let command_line = preferred_command_line(inst).or(command_line);
        let user = inst.user.clone().or(user);
        let label = label.unwrap_or_else(|| {
            image
                .as_deref()
                .and_then(|p| p.rsplit(['\\', '/']).next())
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| format!("pid {}", inst.pid))
        });
        let parent_edge = edge_word(inst);
        let (first_event_ns, last_event_ns, event_count) = counts
            .get(&key)
            .copied()
            .unwrap_or((inst.start_utc_ns, inst.exit_utc_ns, inst.event_ids.len() as i64));
        nodes.insert(
            inst.id.clone(),
            ProcessNode {
                entity_id,
                key: key.clone(),
                instance_id: inst.id.clone(),
                label,
                pid: Some(inst.pid),
                started: inst.start_utc_ns.map(|ns| ProcessStart {
                    ns,
                    iso: Timestamp::new(ns, TsPrecision::HundredNanos, TzSource::NativeUtc)
                        .to_rfc3339(),
                    exact: inst.start_exact,
                }),
                image,
                command_line,
                user,
                elevated,
                access_error,
                event_count,
                first_event_ns,
                last_event_ns,
                max_severity: sev.get(&inst.id).copied().or_else(|| sev.get(&key).copied()),
                parent_edge,
                claimed_ppid: inst.claimed_ppid,
                source_set: inst.source_set.iter().map(|s| s.as_str().to_string()).collect(),
                indicators: inst.indicators.clone(),
                related_logs: Vec::new(),
                related_logs_omitted: 0,
                children: Vec::new(),
            },
        );
    }

    attach_related_logs(conn, forest, &mut nodes)?;

    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    let mut roots: Vec<String> = Vec::new();
    for inst in &forest.instances {
        match (inst.parent_id.as_ref(), inst.parent_edge) {
            (Some(p), EdgeState::Confirmed | EdgeState::Inferred) if nodes.contains_key(p) => {
                children.entry(p.clone()).or_default().push(inst.id.clone());
            }
            _ => roots.push(inst.id.clone()),
        }
    }

    roots.sort_by_key(|k| {
        (
            nodes.get(k).and_then(|n| n.started.as_ref().map(|s| s.ns)).unwrap_or(i64::MAX),
            k.clone(),
        )
    });
    Ok(roots
        .into_iter()
        .map(|k| assemble_forest(&k, &mut nodes, &children, 0))
        .collect())
}

fn edge_word(inst: &tpv_model::ProcessInstance) -> String {
    match (inst.parent_id.as_ref(), inst.parent_edge) {
        (Some(_), EdgeState::Confirmed) => "confirmed".into(),
        (Some(_), EdgeState::Inferred) => "inferred".into(),
        (_, EdgeState::Impossible) => "impossible".into(),
        (_, EdgeState::Orphaned) if inst.pid != 0 && inst.pid != 4 => "orphaned".into(),
        _ => "root".into(),
    }
}

const RELATED_CAP: usize = 24;

/// Hang Event Log / Sysmon / net rows on the process instance they describe.
///
/// Module loads and live snapshots stay off the branch: they drown the Event IDs
/// the analyst actually correlates. A recycled PID is disambiguated by the
/// instance lifetime, so 4688 for the first occupant does not appear under the
/// second.
fn attach_related_logs(
    conn: &Connection,
    forest: &Forest,
    nodes: &mut std::collections::HashMap<String, ProcessNode>,
) -> Result<()> {
    let has_log_id = column_exists(conn, "events", "log_id")?;
    let log_sql = if has_log_id { "e.log_id" } else { "NULL" };
    let sql = format!(
        "SELECT e.id, e.pid, e.ts_utc_ns, e.kind, e.source, {log_sql}, e.summary
         FROM events e
         WHERE e.pid IS NOT NULL
           AND e.kind NOT IN (
             'module_load', 'process_snapshot', 'thread_start',
             'memory_region', 'collector_action'
           )
           AND (
             e.source IN ('evtx', 'journald', 'auditd')
             OR e.kind IN (
               'process_start', 'process_end', 'logon_session',
               'net_connection', 'net_listen', 'service_install',
               'service_state', 'task_register', 'execution_evidence',
               'log_record', 'driver_load'
             )
           )
         ORDER BY e.ts_utc_ns, e.id"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, Option<i64>>(5)?,
            r.get::<_, String>(6)?,
        ))
    })?;

    let mut windows: Vec<(&str, u32, i64, i64)> = forest
        .instances
        .iter()
        .map(|i| {
            let start = i.start_utc_ns.unwrap_or(i64::MIN);
            let end = i.exit_utc_ns.unwrap_or(i64::MAX);
            (i.id.as_str(), i.pid, start, end)
        })
        .collect();
    windows.sort_by_key(|w| (w.1, w.2));

    let mut buckets: std::collections::HashMap<String, Vec<RelatedLog>> =
        std::collections::HashMap::new();
    for row in rows {
        let (id, pid, ts, kind, source, log_col, summary) = row?;
        let log_id = log_col
            .map(|v| v as u32)
            .or_else(|| parse_bracket_id(&summary));
        let pid = pid as u32;
        let Some(inst_id) = windows
            .iter()
            .filter(|w| w.1 == pid && ts + 2_000_000_000 >= w.2 && ts <= w.3.saturating_add(2_000_000_000))
            .min_by_key(|w| (ts.saturating_sub(w.2)).abs())
            .map(|w| w.0)
        else {
            continue;
        };
        buckets.entry(inst_id.to_string()).or_default().push(RelatedLog {
            event_id: id,
            log_id,
            kind,
            source,
            iso: Timestamp::new(ts, TsPrecision::HundredNanos, TzSource::NativeUtc).to_rfc3339(),
            summary,
            ts_ns: ts,
        });
    }

    for (id, mut logs) in buckets {
        logs.sort_by_key(|l| (l.ts_ns, l.event_id));
        let omitted = logs.len().saturating_sub(RELATED_CAP) as i64;
        logs.truncate(RELATED_CAP);
        if let Some(n) = nodes.get_mut(&id) {
            n.related_logs = logs;
            n.related_logs_omitted = omitted;
        }
    }
    Ok(())
}

fn preferred_command_line(inst: &tpv_model::ProcessInstance) -> Option<String> {
    let rank = |s: FieldSource| match s {
        FieldSource::Evtx4688 | FieldSource::Sysmon1 => 0,
        FieldSource::LiveApi => 1,
        FieldSource::MemPeb => 2,
        _ => 3,
    };
    inst.fields
        .iter()
        .filter(|f| f.field == "command_line" && !f.value.is_empty())
        .min_by_key(|f| rank(f.source))
        .map(|f| f.value.clone())
}

struct Attrs {
    id: i64,
    label: String,
    image: Option<String>,
    command_line: Option<String>,
    user: Option<String>,
    elevated: Option<bool>,
    access_error: Option<String>,
}

fn entity_attrs(conn: &Connection) -> Result<HashMapByKey> {
    let mut stmt = conn.prepare(
        "SELECT id, key, label, attrs FROM entities WHERE kind = 'process'",
    )?;
    let mut map = HashMapByKey::default();
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<Vec<u8>>>(3)?,
        ))
    })?;
    for row in rows {
        let (id, key, label, attrs_z) = row?;
        let attrs = attrs_z
            .and_then(|z| zstd::decode_all(&z[..]).ok())
            .and_then(|j| serde_json::from_slice::<serde_json::Value>(&j).ok());
        let text = |k: &str| {
            attrs
                .as_ref()
                .and_then(|a| a.get(k))
                .and_then(|v| v.as_str())
                .map(str::to_owned)
                .filter(|s| !s.is_empty())
        };
        map.0.insert(
            key,
            Attrs {
                id,
                label,
                image: text("image_path"),
                command_line: text("command_line").or_else(|| text("cmdline")),
                user: text("user"),
                elevated: attrs
                    .as_ref()
                    .and_then(|a| a.get("elevated"))
                    .and_then(|v| v.as_bool()),
                access_error: text("access_error"),
            },
        );
    }
    Ok(map)
}

#[derive(Default)]
struct HashMapByKey(std::collections::HashMap<String, Attrs>);

fn lookup_attrs(
    attrs: &HashMapByKey,
    inst: &tpv_model::ProcessInstance,
    key: &str,
) -> (
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<bool>,
    Option<String>,
) {
    let hit = inst
        .entity_keys
        .iter()
        .find_map(|k| attrs.0.get(k))
        .or_else(|| attrs.0.get(key));
    match hit {
        Some(a) => (
            a.id,
            Some(a.label.clone()),
            a.image.clone(),
            a.command_line.clone(),
            a.user.clone(),
            a.elevated,
            a.access_error.clone(),
        ),
        None => (-1, None, None, None, None, None, None),
    }
}

fn event_counts(conn: &Connection) -> Result<std::collections::HashMap<String, (Option<i64>, Option<i64>, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT en.key,
                MIN(ev.ts_utc_ns),
                MAX(ev.ts_utc_ns),
                COUNT(*)
         FROM entities en
         JOIN events ev ON ev.entity_id = en.id
         WHERE en.kind = 'process'
         GROUP BY en.key",
    )?;
    let mut map = std::collections::HashMap::new();
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<i64>>(1)?,
            r.get::<_, Option<i64>>(2)?,
            r.get::<_, i64>(3)?,
        ))
    })?;
    for row in rows {
        let (k, a, b, n) = row?;
        map.insert(k, (a, b, n));
    }
    Ok(map)
}

fn max_severity(conn: &Connection) -> Result<std::collections::HashMap<String, tpv_model::Severity>> {
    let mut stmt = conn.prepare(
        "SELECT en.key, f.severity
         FROM findings f JOIN entities en ON en.id = f.entity_id",
    )?;
    let mut best = std::collections::HashMap::new();
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    for row in rows {
        let (key, sev) = row?;
        let Some(sev) = tpv_model::Severity::from_str_lossy(&sev) else {
            continue;
        };
        best.entry(key)
            .and_modify(|cur: &mut tpv_model::Severity| {
                if sev.rank() > cur.rank() {
                    *cur = sev;
                }
            })
            .or_insert(sev);
    }
    Ok(best)
}

fn assemble_forest(
    key: &str,
    nodes: &mut std::collections::HashMap<String, ProcessNode>,
    children: &std::collections::HashMap<String, Vec<String>>,
    depth: u32,
) -> ProcessNode {
    const MAX_DEPTH: u32 = 64;
    let mut node = nodes.remove(key).unwrap_or_else(|| empty_node(key));
    if depth < MAX_DEPTH {
        if let Some(kids) = children.get(key) {
            let mut kids = kids.clone();
            kids.sort();
            for k in kids {
                if nodes.contains_key(&k) {
                    node.children.push(assemble_forest(&k, nodes, children, depth + 1));
                }
            }
            node.children.sort_by_key(|c| {
                (
                    c.started.as_ref().map(|s| s.ns).unwrap_or(i64::MAX),
                    c.pid,
                )
            });
        }
    }
    node
}

fn empty_node(key: &str) -> ProcessNode {
    ProcessNode {
        entity_id: -1,
        key: key.to_string(),
        instance_id: key.to_string(),
        label: key.to_string(),
        pid: None,
        started: None,
        image: None,
        command_line: None,
        user: None,
        elevated: None,
        access_error: None,
        event_count: 0,
        first_event_ns: None,
        last_event_ns: None,
        max_severity: None,
        parent_edge: "orphaned".into(),
        claimed_ppid: None,
        source_set: Vec::new(),
        indicators: Vec::new(),
        related_logs: Vec::new(),
        related_logs_omitted: 0,
        children: Vec::new(),
    }
}
