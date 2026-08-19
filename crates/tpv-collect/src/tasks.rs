//! Scheduled task XML from `C:\Windows\System32\Tasks`.
//!
//! A shallow walk: the task name, command and author are enough for triage.
//! Broken XML is skipped with a warning. This is not a WMI dump.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tpv_format::CaseWriter;
use tpv_model::{
    AccessMethod, Entity, EntityKind, Event, EventKind, ManifestEntry, Source, Timestamp,
};

use crate::error::Result;

pub fn write_tasks(
    w: &mut CaseWriter,
    observed: Timestamp,
    cancel: &Arc<AtomicBool>,
) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    let root = tasks_dir();
    if !root.is_dir() {
        let msg = format!("scheduled tasks directory not present: {}", root.display());
        warnings.push(msg.clone());
        w.add_manifest(&gap(&root, observed, msg))?;
        return Ok(warnings);
    }

    let inferred = observed.inferred();
    let mut emitted = 0u64;
    walk(&root, &root, w, inferred, cancel, &mut emitted, &mut warnings)?;

    w.add_manifest(&ManifestEntry {
        source_path: root.display().to_string(),
        method: AccessMethod::Win32File,
        size_bytes: 0,
        sha256: None,
        started: observed,
        finished: observed,
        events_emitted: emitted,
        error: None,
    })?;
    Ok(warnings)
}

fn walk(
    root: &Path,
    dir: &Path,
    w: &mut CaseWriter,
    inferred: Timestamp,
    cancel: &Arc<AtomicBool>,
    emitted: &mut u64,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let rd = match std::fs::read_dir(dir) {
        Ok(it) => it,
        Err(e) => {
            warnings.push(format!("{}: {e}", dir.display()));
            return Ok(());
        }
    };
    for ent in rd {
        if cancel.load(Ordering::Relaxed) {
            warnings.push("scheduled task ingest interrupted by operator".into());
            return Ok(());
        }
        let Ok(ent) = ent else { continue };
        let path = ent.path();
        if path.is_dir() {
            walk(root, &path, w, inferred, cancel, emitted, warnings)?;
            continue;
        }
        match ingest_one(w, root, &path, inferred) {
            Ok(n) => *emitted += n,
            Err(e) => warnings.push(format!("{}: {e}", path.display())),
        }
    }
    Ok(())
}

fn ingest_one(w: &mut CaseWriter, root: &Path, path: &Path, inferred: Timestamp) -> Result<u64> {
    let xml = std::fs::read_to_string(path)?;
    if !xml.contains("<Task") && !xml.contains("<task") {
        return Ok(0);
    }
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('/', "\\");
    let command = xml_tag(&xml, "Command");
    let args = xml_tag(&xml, "Arguments");
    let author = xml_tag(&xml, "Author").or_else(|| xml_tag(&xml, "UserId"));
    let cmdline = match (command.as_deref(), args.as_deref()) {
        (Some(c), Some(a)) => format!("{c} {a}"),
        (Some(c), None) => c.to_string(),
        _ => String::new(),
    };

    let key = format!("task:{rel}");
    w.upsert_entity(&Entity::new(EntityKind::ScheduledTask, &key, &rel))?;

    let summary = if cmdline.is_empty() {
        format!("scheduled task {rel}")
    } else {
        format!("scheduled task {rel}: {cmdline}")
    };

    let mut ev = Event::new(
        inferred,
        Source::ScheduledTasks,
        EventKind::TaskRegister,
        summary,
    )
    .with_path(&rel)
    .with_payload(serde_json::json!({
        "task": rel,
        "command": command,
        "arguments": args,
        "author": author,
        "source": path.display().to_string(),
    }));
    if let Some(c) = command {
        ev.image = Some(c);
    }
    if let Some(a) = author {
        ev.user = Some(a);
    }
    w.add_event(&ev)?;
    Ok(1)
}

fn xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let v = xml[start..end].trim();
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

fn tasks_dir() -> PathBuf {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    root.join("System32").join("Tasks")
}

fn gap(path: &Path, observed: Timestamp, error: String) -> ManifestEntry {
    ManifestEntry {
        source_path: path.display().to_string(),
        method: AccessMethod::Win32File,
        size_bytes: 0,
        sha256: None,
        started: observed,
        finished: observed,
        events_emitted: 0,
        error: Some(error),
    }
}
