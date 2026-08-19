//! Collection orchestration.
//!
//! Order of volatility is the organising principle and it is not negotiable:
//! the reference clock first, then network state, then processes, then the
//! comparatively stable configuration. Reading disk artifacts before the process
//! list would mean the process list describes a machine that has already moved
//! on, and the correlation between the two would be quietly wrong.
//!
//! The other invariant is that a collection never aborts because one source
//! failed. During an incident a partial case with recorded gaps beats a clean
//! error, so every failure becomes a manifest row or a custody warning and the
//! run continues.

#![forbid(unsafe_code)]

pub mod error;
pub mod evtx;
pub mod footprint;
#[cfg(windows)]
pub mod images;
pub mod memory;
pub mod outname;
pub mod prefetch;
pub mod tasks;

#[cfg(windows)]
pub mod live_win;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tpv_format::{CaseInit, CaseSummary, CaseWriter};
use tpv_model::{CaseId, CollectionProfile, Custody, Timestamp};

pub use error::{CollectError, Result};
pub use footprint::{Footprint, LocationVerdict};
pub use outname::{default_filename, resolve_out};

/// Turn `--out` (file, directory or omitted) into the case path.
#[cfg(windows)]
pub fn resolve_collect_out(out: Option<PathBuf>) -> PathBuf {
    let host = tpv_live_win::hostinfo::capture();
    let at = live_win::observed_at(&host);
    resolve_out(out.as_deref(), &host.hostname, at)
}

#[cfg(not(windows))]
pub fn resolve_collect_out(out: Option<PathBuf>) -> PathBuf {
    let at = Timestamp::new(0, tpv_model::TsPrecision::Second, tpv_model::TzSource::NativeUtc);
    resolve_out(out.as_deref(), "host", at)
}

/// What to collect and where to put it.
#[derive(Debug, Clone)]
pub struct CollectConfig {
    pub out: PathBuf,
    pub tool_version: String,
    pub profile: CollectionProfile,
    /// Recorded verbatim in the custody record, because the flags used are what
    /// determine which absences in the case are meaningful.
    pub command_line: String,
    /// Set by the CLI Ctrl+C handler. Collection finishes and seals the case.
    pub cancel: Arc<AtomicBool>,
}

impl CollectConfig {
    fn stopped(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
}

fn progress(step: u32, total: u32, msg: &str) {
    eprintln!("  [{step}/{total}] {msg}");
}

/// Run a collection and produce a finished case.
#[cfg(windows)]
pub fn run(cfg: &CollectConfig) -> Result<CaseSummary> {
    use tpv_live_win::{LiveOptions, ProcessOptions};

    let mut footprint = Footprint::default();

    match footprint::check_output(&cfg.out, cfg.profile.allow_local_write) {
        LocationVerdict::External => {}
        LocationVerdict::LocalAccepted { warning } => footprint.warn(warning),
        LocationVerdict::Refused { reason } => {
            return Err(CollectError::UnsafeOutput {
                path: cfg.out.clone(),
                reason,
            })
        }
    }

    let me = tpv_live_win::selfinfo::capture();
    if !me.elevated {
        eprintln!(
            "collector is not elevated: Security.evtx, LSASS command line, VSS and registry \
             hives may be missing; collection continues"
        );
        footprint.warn(
            "collector is not elevated: raw volume, VSS and registry hives are unavailable, \
             and some processes could not be inspected",
        );
    } else {
        eprintln!("collector is elevated");
    }

    let disk = cfg.profile.disk_artifacts;
    let evtx_on = cfg.profile.event_logs;
    // host, snapshot, optional disk (images+prefetch+tasks), optional evtx, seal
    let total = 2 + if disk { 3 } else { 0 } + if evtx_on { 1 } else { 0 } + 1;
    let mut step = 1u32;

    progress(step, total, "host identity and reference clock");
    step += 1;
    let host = tpv_live_win::hostinfo::capture();
    let started = live_win::observed_at(&host);

    let mut writer = CaseWriter::create(
        &cfg.out,
        CaseInit {
            case_id: CaseId::generate(),
            tool_version: cfg.tool_version.clone(),
            host: live_win::host_info(&host),
            clock: live_win::reference_clock(&host),
            profile: cfg.profile.clone(),
        },
    )?;
    footprint.wrote(&cfg.out);

    let mut snapshot = tpv_live_win::LiveSnapshot::default();
    if !cfg.stopped() {
        progress(step, total, "volatile state (network, processes, services)");
        step += 1;
        snapshot = tpv_live_win::collect(LiveOptions {
            processes: ProcessOptions::default(),
            network: cfg.profile.live_state,
            services: cfg.profile.live_state,
            drivers: cfg.profile.live_state,
            autoruns: cfg.profile.live_state,
        });
        for w in &snapshot.warnings {
            footprint.warn(w.clone());
        }
        eprintln!(
            "    {} processes, {} endpoints, {} services",
            snapshot.processes.len(),
            snapshot.endpoints.len(),
            snapshot.services.len()
        );
    } else {
        step += 1;
    }

    let mut image_hashes = HashMap::new();
    if disk && !cfg.stopped() {
        progress(step, total, "SHA-256 of process images");
        step += 1;
        let (hashes, ws) = images::hash_snapshot_images(&snapshot, &cfg.cancel);
        image_hashes = hashes;
        for w in &ws {
            footprint.warn(w.clone());
        }
        eprintln!("    {} unique images hashed", image_hashes.len());
        images::write_manifest(&mut writer, &image_hashes, &ws, started)?;
    } else if disk {
        step += 1;
    }

    live_win::write_snapshot(&mut writer, &snapshot, started, &image_hashes)?;

    if disk && !cfg.stopped() {
        progress(step, total, "prefetch");
        step += 1;
        match prefetch::write_prefetch(&mut writer, started, &cfg.cancel) {
            Ok(ws) => {
                for w in ws {
                    footprint.warn(w);
                }
            }
            Err(e) => footprint.warn(format!("prefetch: {e}")),
        }
        progress(step, total, "scheduled tasks");
        step += 1;
        match tasks::write_tasks(&mut writer, started, &cfg.cancel) {
            Ok(ws) => {
                for w in ws {
                    footprint.warn(w);
                }
            }
            Err(e) => footprint.warn(format!("scheduled tasks: {e}")),
        }
    } else if disk {
        step += 2;
    }

    if evtx_on && !cfg.stopped() {
        progress(step, total, "Windows event logs");
        step += 1;
        match evtx::write_logs(
            &mut writer,
            started,
            cfg.profile.evtx_max_records,
            &cfg.cancel,
        ) {
            Ok(ws) => {
                for w in ws {
                    footprint.warn(w);
                }
            }
            Err(e) => footprint.warn(format!("event logs: {e}")),
        }
    } else if evtx_on {
        step += 1;
    }

    if cfg.stopped() {
        footprint.warn("collection interrupted by operator");
        eprintln!("  interrupted — sealing the case with what was gathered");
    }

    progress(step, total, "sealing case");
    let finished = live_win::observed_at(&tpv_live_win::hostinfo::capture());
    let summary = writer.finish(Custody {
        collector_version: cfg.tool_version.clone(),
        collector_pid: me.pid,
        collector_image: me.image.clone(),
        collector_sha256: hash_own_binary(&me.image),
        command_line: cfg.command_line.clone(),
        started,
        finished,
        run_as_user: snapshot
            .processes
            .iter()
            .find(|p| p.pid == me.pid)
            .and_then(|p| p.user.clone())
            .unwrap_or_else(|| "unknown".into()),
        elevated: me.elevated,
        files_written: footprint
            .files_written
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        warnings: footprint.warnings.clone(),
    })?;

    Ok(summary)
}

#[cfg(not(windows))]
pub fn run(_cfg: &CollectConfig) -> Result<CaseSummary> {
    Err(CollectError::UnsupportedPlatform)
}

/// Hash the collector binary so the case identifies exactly which build made it.
///
/// Failure is not fatal: the tool may have been deleted or locked underneath
/// itself, and a case without this hash is still a case.
fn hash_own_binary(path: &str) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    tpv_format::hash::sha256_stream(&mut f).ok().map(|(h, _)| h)
}

/// Duration of a collection, for reporting.
pub fn elapsed_ms(started: Timestamp, finished: Timestamp) -> i64 {
    (finished.utc_ns - started.utc_ns) / 1_000_000
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use tpv_format::{CaseReader, EventFilter};
    use tpv_model::MemoryMode;

    fn config(out: PathBuf) -> CollectConfig {
        CollectConfig {
            out,
            tool_version: "tpv/test".into(),
            profile: CollectionProfile {
                memory: MemoryMode::None,
                selected_pids: vec![],
                live_state: true,
                disk_artifacts: false,
                event_logs: false,
                evtx_max_records: None,
                prefer_vss: false,
                max_ram_mib: Some(256),
                // The temp directory is on the system volume, so a test
                // collection is exactly the case the footprint guard refuses.
                allow_local_write: true,
            },
            command_line: "tpv collect --out <temp>".into(),
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    #[test]
    fn a_collection_produces_a_verifiable_case_of_this_host() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("case.tpv");
        let summary = run(&config(out.clone())).unwrap();

        assert!(summary.events > 0, "a live host always has processes");
        assert!(summary.entities > 0);

        let r = CaseReader::open(&out).unwrap();
        assert!(r.verify_content_digest().unwrap());

        let meta = r.meta().unwrap();
        assert!(meta.finalized);
        assert!(!meta.host.hostname.is_empty());

        let custody = meta.custody.expect("custody is written on finish");
        assert_eq!(custody.collector_pid, std::process::id());
        assert!(
            custody
                .warnings
                .iter()
                .any(|w| w.contains("volume under examination")),
            "writing to the system volume must be recorded: {:?}",
            custody.warnings
        );
        assert!(custody
            .files_written
            .iter()
            .any(|f| f.contains("case.tpv")));
    }

    #[test]
    fn the_collector_finds_itself_in_its_own_case() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("case.tpv");
        run(&config(out.clone())).unwrap();

        let r = CaseReader::open(&out).unwrap();
        let mine = r
            .events(
                &EventFilter {
                    pids: vec![std::process::id()],
                    ..Default::default()
                },
                16,
                0,
            )
            .unwrap();
        assert!(
            !mine.is_empty(),
            "the collector must appear in the process list it collected"
        );
    }

    #[test]
    fn the_process_tree_is_connected_rather_than_a_flat_list() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("case.tpv");
        run(&config(out.clone())).unwrap();

        let roots = CaseReader::open(&out).unwrap().process_tree().unwrap();
        assert!(!roots.is_empty());

        fn depth(n: &tpv_format::ProcessNode) -> u32 {
            1 + n.children.iter().map(depth).max().unwrap_or(0)
        }
        let deepest = roots.iter().map(depth).max().unwrap();
        assert!(
            deepest >= 3,
            "a real Windows host nests at least System > wininit > services; got depth {deepest}"
        );
    }

    #[test]
    fn refusing_the_examined_volume_is_an_error_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("refused.tpv");
        let mut cfg = config(out.clone());
        cfg.profile.allow_local_write = false;

        match run(&cfg) {
            Err(CollectError::UnsafeOutput { .. }) => {}
            other => panic!("expected a refusal, got {:?}", other.map(|s| s.events)),
        }
        assert!(!out.exists(), "a refused collection must not create the file");
    }

    #[test]
    fn interrupting_before_sources_still_seals_a_verifiable_case() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("stopped.tpv");
        let cfg = config(out.clone());
        cfg.cancel.store(true, Ordering::Relaxed);

        let summary = run(&cfg).unwrap();
        assert!(out.exists());
        let r = CaseReader::open(&out).unwrap();
        assert!(r.verify_content_digest().unwrap());
        let meta = r.meta().unwrap();
        assert!(meta.finalized);
        let custody = meta.custody.expect("sealed");
        assert!(
            custody
                .warnings
                .iter()
                .any(|w| w.contains("interrupted by operator")),
            "{:?}",
            custody.warnings
        );
        let _ = summary;
    }
}
