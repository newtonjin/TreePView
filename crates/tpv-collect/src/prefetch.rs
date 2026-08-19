//! Prefetch files as execution evidence.
//!
//! Read after the volatile snapshot and before the event-log ingest, so a
//! process that already exited still has a run record in the case. Parse
//! failures and access denied become manifest gaps.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tpv_format::CaseWriter;
use tpv_model::{
    normalize_path, AccessMethod, Entity, Event, EventKind, ManifestEntry, Source, Timestamp,
};

use crate::error::Result;

/// Ingest `%SystemRoot%\Prefetch\*.pf`.
pub fn write_prefetch(
    w: &mut CaseWriter,
    observed: Timestamp,
    cancel: &Arc<AtomicBool>,
) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    let dir = prefetch_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(it) => it,
        Err(e) => {
            let msg = format!("prefetch directory {}: {e}", dir.display());
            warnings.push(msg.clone());
            w.add_manifest(&gap(&dir, observed, msg))?;
            return Ok(warnings);
        }
    };

    let mut emitted = 0u64;
    let mut hashed = 0u64;
    for ent in entries {
        if cancel.load(Ordering::Relaxed) {
            warnings.push("prefetch ingest interrupted by operator".into());
            break;
        }
        let Ok(ent) = ent else { continue };
        let path = ent.path();
        if !path
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("pf"))
        {
            continue;
        }
        match ingest_one(w, &path, observed) {
            Ok(n) => {
                emitted += n;
                hashed += 1;
            }
            Err(e) => warnings.push(format!("{}: {e}", path.display())),
        }
    }

    w.add_manifest(&ManifestEntry {
        source_path: dir.display().to_string(),
        method: AccessMethod::Win32File,
        size_bytes: 0,
        sha256: None,
        started: observed,
        finished: observed,
        events_emitted: emitted,
        error: (!warnings.is_empty()).then(|| format!("{} files had errors", warnings.len())),
    })?;
    let _ = hashed;
    Ok(warnings)
}

fn ingest_one(w: &mut CaseWriter, path: &Path, observed: Timestamp) -> Result<u64> {
    let bytes = std::fs::read(path)?;
    let info = prefetch_core::parse(&bytes).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e:?}"))
    })?;

    let exe = info.executable.clone();
    let ts = last_run_ts(&info).unwrap_or(observed.inferred());
    let file_key = if let Some(mapped) = info.filenames.iter().find(|f| {
        f.rsplit(['\\', '/'])
            .next()
            .is_some_and(|b| b.eq_ignore_ascii_case(&exe))
    }) {
        normalize_path(mapped)
    } else {
        normalize_path(&exe)
    };

    w.upsert_entity(&Entity::file(&file_key))?;

    let mut ev = Event::new(
        ts,
        Source::Prefetch,
        EventKind::ExecutionEvidence,
        format!(
            "{} prefetch runs={} files={}",
            exe, info.run_count, info.filenames.len()
        ),
    )
    .with_path(path.to_string_lossy().as_ref())
    .with_payload(serde_json::json!({
        "executable": exe,
        "version": info.version,
        "run_count": info.run_count,
        "filenames": info.filenames,
        "source": path.display().to_string(),
    }));
    ev.image = Some(exe);
    w.add_event(&ev)?;
    Ok(1)
}

fn last_run_ts(info: &prefetch_core::PrefetchInfo) -> Option<Timestamp> {
    let ticks = *info.last_run_times.first().filter(|t| **t > 0)?;
    Some(Timestamp::from_filetime(ticks as i64))
}

fn prefetch_dir() -> PathBuf {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    root.join("Prefetch")
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
