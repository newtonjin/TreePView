//! Turning a memory image into a case.
//!
//! A memory image is analysed on the examiner's machine, not the subject's, so
//! this path has none of the volatility ordering or footprint constraints of a
//! live collection. What it does have is a stronger claim to make: the image is
//! a fixed artifact, so every fact derived from it is reproducible, and the
//! case records the image's hash to let anyone check that.
//!
//! The distinction the case has to preserve is *how* each process was found.
//! A process the kernel still lists and a process found only in the pool are
//! different claims, and only the second one is interesting. That difference
//! survives into the entity attributes and into the event summary, so it is
//! visible in the viewer without the analyst having to know to look for it.

use std::path::{Path, PathBuf};

use tpv_format::{CaseInit, CaseSummary, CaseWriter};
use tpv_memory::{Analysis, Discovery, GuestOs, MemProcess};
use tpv_model::{
    entity::ProcessKey, normalize_path, AccessMethod, CaseId, CollectionProfile, Custody, Edge,
    EdgeKind, Entity, EntityKind, Event, EventKind, HostInfo, ManifestEntry, MemoryMode,
    ReferenceClock, Source, Timestamp, TsPrecision, TzSource,
};

use crate::error::Result;

/// What to analyse and where to put the result.
#[derive(Debug, Clone)]
pub struct MemoryConfig {
    pub image: PathBuf,
    pub out: PathBuf,
    pub tool_version: String,
    pub command_line: String,
}

/// Analyse an image and write a case describing it.
pub fn run(cfg: &MemoryConfig) -> Result<CaseSummary> {
    let started = now();
    let (image_sha256, image_bytes) = hash_file(&cfg.image);

    let analysis = Analysis::open(&cfg.image)?;
    let (os_name, os_version) = match analysis.os() {
        GuestOs::Linux => (
            "Linux (recovered from a memory image)".into(),
            analysis.linux_banner().unwrap_or_default().to_string(),
        ),
        GuestOs::Windows => ("Windows (recovered from a memory image)".into(), String::new()),
    };

    let mut writer = CaseWriter::create(
        &cfg.out,
        CaseInit {
            case_id: CaseId::generate(),
            tool_version: cfg.tool_version.clone(),
            // A memory image does not tell us its own hostname without parsing
            // the registry, which is a later milestone. Claiming the examiner's
            // hostname here would be a lie the viewer would then display, so the
            // fields stay empty and honest.
            host: HostInfo {
                hostname: image_label(&cfg.image),
                os_name,
                os_version,
                architecture: "x86_64".into(),
                domain: None,
                machine_id: None,
                timezone_name: None,
                utc_offset_minutes: None,
                boot_time: None,
            },
            // The image has no clock of its own that we can read yet, so the
            // reference is the examiner's, and it is recorded as such rather
            // than presented as the subject machine's.
            clock: ReferenceClock { host_utc: started, monotonic_uptime_ms: None },
            profile: CollectionProfile {
                memory: MemoryMode::ImageAnalysis,
                selected_pids: vec![],
                live_state: false,
                disk_artifacts: false,
                event_logs: false,
                evtx_max_records: None,
                prefer_vss: false,
                max_ram_mib: None,
                allow_local_write: true,
            },
        },
    )?;

    writer.add_manifest(&ManifestEntry {
        source_path: cfg.image.display().to_string(),
        method: AccessMethod::Win32File,
        size_bytes: image_bytes,
        sha256: image_sha256.clone(),
        started,
        finished: now(),
        events_emitted: 0,
        error: None,
    })?;

    // How the process list was recovered is evidence about the analysis itself.
    match analysis.os() {
        GuestOs::Windows => {
            let profile = analysis.profile().expect("Windows analysis carries a kernel profile");
            writer.add_event(
                &Event::new(
                    started.inferred(),
                    Source::Collector,
                    EventKind::CollectorAction,
                    format!(
                        "calibrated the kernel layout from the image itself: {} linked entries, \
                         {}% field agreement, page-table root {:#x}",
                        profile.linked_entries, profile.agreement, profile.kernel_dtb
                    ),
                )
                .with_payload(serde_json::json!({
                    "image": cfg.image.display().to_string(),
                    "image_sha256": image_sha256,
                    "image_format": analysis.memory().format().as_str(),
                    "os": "windows",
                    "captured_bytes": analysis.memory().captured_bytes(),
                    "runs": analysis.memory().runs().len(),
                    "layout": profile.layout,
                    "agreement_percent": profile.agreement,
                })),
            )?;
        }
        GuestOs::Linux => {
            let via = if analysis.processes().iter().any(|p| p.discovery == Discovery::ElfNotes) {
                "ELF core notes"
            } else if analysis.processes().iter().any(|p| p.discovery == Discovery::Heuristic) {
                "a Linux task_struct scan"
            } else {
                "the image format (no process list recovered)"
            };
            writer.add_event(
                &Event::new(
                    started.inferred(),
                    Source::Collector,
                    EventKind::CollectorAction,
                    format!(
                        "recovered {} process(es) from {via}{}",
                        analysis.processes().len(),
                        analysis
                            .linux_banner()
                            .map(|b| format!("; {b}"))
                            .unwrap_or_default()
                    ),
                )
                .with_payload(serde_json::json!({
                    "image": cfg.image.display().to_string(),
                    "image_sha256": image_sha256,
                    "image_format": analysis.memory().format().as_str(),
                    "os": "linux",
                    "banner": analysis.linux_banner(),
                    "captured_bytes": analysis.memory().captured_bytes(),
                    "runs": analysis.memory().runs().len(),
                })),
            )?;
        }
    }

    write_processes(&mut writer, &analysis)?;

    let finished = now();
    let summary = writer.finish(Custody {
        collector_version: cfg.tool_version.clone(),
        collector_pid: std::process::id(),
        collector_image: std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        collector_sha256: None,
        command_line: cfg.command_line.clone(),
        started,
        finished,
        run_as_user: "examiner".into(),
        elevated: false,
        files_written: vec![cfg.out.display().to_string()],
        warnings: warnings(&analysis),
    })?;

    Ok(summary)
}

fn warnings(analysis: &Analysis) -> Vec<String> {
    let mut out = Vec::new();
    match analysis.os() {
        GuestOs::Windows => {
            let Some(p) = analysis.profile() else { return out };
            if p.agreement < 90 {
                out.push(format!(
                    "the recovered kernel structure layout agreed with only {}% of process entries; \
                     fields may be misread and the process list should be corroborated",
                    p.agreement
                ));
            }
            // Without this field there are no command lines, no image paths and no
            // module lists in the whole case. An analyst seeing empty command lines
            // needs to know it was unrecoverable rather than genuinely empty.
            if p.layout.peb.is_none() {
                out.push(
                    "the PEB pointer could not be located in this image, so no command line, \
                     image path or loaded module could be read; blank fields here mean \
                     unrecovered, not absent"
                        .into(),
                );
            }
            let hidden = analysis.hidden().count();
            if hidden > 0 {
                out.push(format!(
                    "{hidden} process(es) were found in the pool but not in the kernel's process list"
                ));
            }
        }
        GuestOs::Linux => {
            if analysis.processes().iter().any(|p| p.discovery == Discovery::Heuristic) {
                out.push(
                    "the Linux process list was recovered by scanning for task_struct-shaped \
                     names; PIDs and parentage may be wrong and should be corroborated"
                        .into(),
                );
            }
            if analysis.processes().is_empty() {
                out.push(
                    "no processes were recovered from this Linux image; ELF core notes were \
                     absent and a task_struct scan did not find kthreadd"
                        .into(),
                );
            }
        }
    }
    out
}

fn write_processes(w: &mut CaseWriter, analysis: &Analysis) -> Result<()> {
    let keys: std::collections::HashMap<u64, ProcessKey> = analysis
        .processes()
        .iter()
        .map(|p| (p.pid, key_for(p)))
        .collect();

    for p in analysis.processes() {
        let key = keys[&p.pid];
        let natural = key.natural_key();

        w.upsert_entity(
            &Entity::process(key, &p.name).with_attrs(serde_json::json!({
                "name": p.name,
                "image_path": p.image_path,
                "command_line": p.command_line,
                "current_directory": p.current_directory,
                "discovery": discovery_word(p.discovery),
                "hidden_from_process_list": p.hidden_from_list(),
                "directory_table_base": format!("{:#x}", p.dtb),
                "eprocess_physical": p.eprocess_pa.map(|v| format!("{v:#x}")),
                "peb": p.peb_va.map(|v| format!("{v:#x}")),
                "module_count": p.modules.len(),
                "exited": p.exit_time != 0,
            })),
        )?;

        let ts = if p.create_time != 0 {
            Timestamp::from_filetime(p.create_time as i64)
        } else {
            now().inferred()
        };

        let mut event = Event::new(
            ts,
            Source::Memory,
            EventKind::ProcessSnapshot,
            summary_line(p),
        )
        .with_entity(&natural)
        .with_payload(serde_json::json!({
            "command_line": p.command_line,
            "current_directory": p.current_directory,
            "discovery": discovery_word(p.discovery),
            "directory_table_base": format!("{:#x}", p.dtb),
            "eprocess_physical": p.eprocess_pa.map(|v| format!("{v:#x}")),
        }));
        event.pid = Some(p.pid as u32);
        event.ppid = Some(p.ppid as u32);
        event.image = p.image_path.clone();
        w.add_event(&event)?;

        if p.exit_time != 0 {
            let mut exited = Event::new(
                Timestamp::from_filetime(p.exit_time as i64),
                Source::Memory,
                EventKind::ProcessEnd,
                format!("{} (pid {}) had exited", p.name, p.pid),
            )
            .with_entity(&natural);
            exited.pid = Some(p.pid as u32);
            w.add_event(&exited)?;
        }

        if let Some(parent) = keys.get(&p.ppid) {
            let plausible = parent.is_pid_only()
                || key.is_pid_only()
                || parent.start_ns <= key.start_ns;
            if plausible && p.ppid != p.pid {
                w.add_edge(&Edge::new(
                    parent.natural_key(),
                    &natural,
                    EdgeKind::ParentOf,
                    Source::Memory,
                ))?;
            }
        }

        if let Some(image) = &p.image_path {
            let file_key = normalize_path(image);
            w.upsert_entity(&Entity::file(image))?;
            w.add_edge(&Edge::new(&natural, &file_key, EdgeKind::ExecutedImage, Source::Memory))?;
        }

        for m in &p.modules {
            let module_key = normalize_path(&m.full_name);
            let short = m
                .full_name
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or(&m.full_name)
                .to_string();
            w.upsert_entity(&Entity::new(EntityKind::Module, &module_key, &short))?;
            w.add_edge(&Edge::new(&natural, &module_key, EdgeKind::LoadedModule, Source::Memory))?;

            let mut load = Event::new(
                now().inferred(),
                Source::Memory,
                EventKind::ModuleLoad,
                format!("{short} mapped at {:#x} in {} (pid {})", m.base, p.name, p.pid),
            )
            .with_entity(&module_key)
            .with_payload(serde_json::json!({
                "base": format!("{:#x}", m.base),
                "size": m.size,
                "full_name": m.full_name,
            }));
            load.pid = Some(p.pid as u32);
            load.image = p.image_path.clone();
            w.add_event(&load)?;
        }
    }
    Ok(())
}

fn summary_line(p: &MemProcess) -> String {
    let where_from = match p.discovery {
        Discovery::Unlinked if p.exit_time != 0 => {
            " — found in the pool only; it had already exited"
        }
        Discovery::Unlinked => {
            " — found in the pool but MISSING from the kernel's process list"
        }
        _ => "",
    };
    match &p.command_line {
        Some(cmd) => format!("{} (pid {}): {}{}", p.name, p.pid, cmd, where_from),
        None => format!("{} (pid {}){}", p.name, p.pid, where_from),
    }
}

fn discovery_word(d: Discovery) -> &'static str {
    match d {
        Discovery::Linked => "process list",
        Discovery::Unlinked => "pool scan only",
        Discovery::Both => "process list and pool scan",
        Discovery::ElfNotes => "ELF core notes",
        Discovery::Heuristic => "Linux task scan",
    }
}

/// A key that survives PID reuse, using the creation time when the image had one.
fn key_for(p: &MemProcess) -> ProcessKey {
    if p.create_time == 0 {
        return ProcessKey::pid_only(p.pid as u32);
    }
    let ts = Timestamp::from_filetime(p.create_time as i64);
    if ts.is_suspect() {
        ProcessKey::pid_only(p.pid as u32)
    } else {
        ProcessKey::new(p.pid as u32, ts.utc_ns)
    }
}

/// The examiner's clock, which is the only one available when reading an image.
fn now() -> Timestamp {
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    Timestamp::new(since_epoch, TsPrecision::HundredNanos, TzSource::NativeUtc)
}

fn image_label(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "memory image".into())
}

fn hash_file(path: &Path) -> (Option<String>, u64) {
    match std::fs::File::open(path) {
        Ok(mut f) => match tpv_format::hash::sha256_stream(&mut f) {
            Ok((h, n)) => (Some(h), n),
            Err(_) => (None, 0),
        },
        Err(_) => (None, 0),
    }
}
