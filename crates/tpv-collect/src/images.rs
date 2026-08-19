//! SHA-256 of running process images.
//!
//! Hashes the on-disk file for each unique image path in the live snapshot.
//! Access denied is a gap on that path, never an abort: LSASS and other
//! protected binaries routinely cannot be read unelevated.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tpv_format::CaseWriter;
use tpv_live_win::LiveSnapshot;
use tpv_model::{
    normalize_path, AccessMethod, Entity, ManifestEntry, Timestamp,
};

use crate::error::Result;

/// Hash unique image paths; key is the normalized path used as the file entity.
pub fn hash_snapshot_images(
    snap: &LiveSnapshot,
    cancel: &Arc<AtomicBool>,
) -> (HashMap<String, String>, Vec<String>) {
    let mut cache: HashMap<String, String> = HashMap::new();
    let mut warnings = Vec::new();
    for p in &snap.processes {
        if cancel.load(Ordering::Relaxed) {
            warnings.push("process image hashing interrupted by operator".into());
            break;
        }
        let Some(path) = p.image_path.as_deref() else { continue };
        let key = normalize_path(path);
        if cache.contains_key(&key) {
            continue;
        }
        match hash_file(Path::new(path)) {
            Some(h) => {
                cache.insert(key, h);
            }
            None => warnings.push(format!("could not hash {path}")),
        }
    }
    (cache, warnings)
}

/// Attach hashes already computed onto file entities (process events carry the
/// digest in their payload from [`super::live_win`]).
pub fn write_manifest(
    w: &mut CaseWriter,
    hashes: &HashMap<String, String>,
    warnings: &[String],
    observed: Timestamp,
) -> Result<()> {
    w.add_manifest(&ManifestEntry {
        source_path: "live://windows/process-images".into(),
        method: AccessMethod::Win32File,
        size_bytes: 0,
        sha256: None,
        started: observed,
        finished: observed,
        events_emitted: hashes.len() as u64,
        error: (!warnings.is_empty()).then(|| warnings.join("; ")),
    })?;
    for (path, sha) in hashes {
        w.upsert_entity(
            &Entity::file(path).with_attrs(serde_json::json!({ "sha256": sha, "path": path })),
        )?;
    }
    Ok(())
}

fn hash_file(path: &Path) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    tpv_format::hash::sha256_stream(&mut f).ok().map(|(h, _)| h)
}
