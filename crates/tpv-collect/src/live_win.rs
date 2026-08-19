//! Turning a live Windows snapshot into timeline events.
//!
//! This is where OS-specific structs become the neutral model. The interesting
//! decisions are about *time*: most of what a live snapshot contains was
//! observed now but happened earlier, or has no meaningful time at all, and
//! pretending otherwise would produce a timeline full of false simultaneity.
//! Anything without a real timestamp is placed at the collection instant and
//! marked [`TsFlags::INFERRED`], so the viewer can render it as observation
//! rather than occurrence.

use std::collections::HashMap;

use tpv_format::CaseWriter;
use tpv_live_win::{LiveProcess, LiveSnapshot};
use tpv_model::{
    entity::ProcessKey, normalize_path, AccessMethod, Edge, EdgeKind, Entity, EntityKind, Event,
    EventKind, ManifestEntry, Source, Timestamp, TsPrecision, TzSource,
};

use crate::error::Result;

/// Natural key for a network endpoint.
fn endpoint_key(proto: &str, local: &str, remote: Option<&str>) -> String {
    match remote {
        Some(r) => format!("net:{proto}:{local}>{r}"),
        None => format!("net:{proto}:{local}"),
    }
}

/// Short name to display for a process.
///
/// Deliberately never the full path. Whether we obtained the path depends on
/// whether the process could be opened, so using it as the label would make the
/// tree's shape reflect the collector's privileges rather than the host: the
/// same binary would render two different ways in one listing. The full path is
/// still carried on the entity and on every event, where the analyst compares it
/// against the expected location.
fn process_label(p: &LiveProcess) -> String {
    if !p.name.is_empty() {
        return p.name.clone();
    }
    p.image_path
        .as_deref()
        .and_then(|path| path.rsplit(['\\', '/']).next())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("pid {}", p.pid))
}

/// The process key, using the creation time when it is known.
///
/// Falling back to a PID-only key is a real loss of fidelity, so it is made
/// explicit in the model rather than papered over with a zero timestamp that
/// would look like a genuine 1970 creation.
fn process_key(p: &LiveProcess) -> ProcessKey {
    match p.create_time_filetime {
        Some(ft) => {
            let ts = Timestamp::from_filetime(ft);
            if ts.is_suspect() {
                ProcessKey::pid_only(p.pid)
            } else {
                ProcessKey::new(p.pid, ts.utc_ns)
            }
        }
        None => ProcessKey::pid_only(p.pid),
    }
}

/// Write everything in a live snapshot into the case.
///
/// `observed` is the collection instant, used for facts that have no time of
/// their own.
pub fn write_snapshot(
    w: &mut CaseWriter,
    snap: &LiveSnapshot,
    observed: Timestamp,
    image_hashes: &HashMap<String, String>,
) -> Result<u64> {
    let inferred = observed.inferred();
    let before = w.event_count();

    write_processes(w, snap, observed, inferred, image_hashes)?;
    write_endpoints(w, snap, inferred)?;
    write_services(w, snap, inferred)?;
    write_drivers(w, snap, inferred)?;
    write_autoruns(w, snap, inferred)?;

    let emitted = w.event_count() - before;

    w.add_manifest(&ManifestEntry {
        source_path: "live://windows/volatile-state".into(),
        method: AccessMethod::LiveApi,
        size_bytes: 0,
        sha256: None,
        started: observed,
        finished: observed,
        events_emitted: emitted,
        error: (!snap.warnings.is_empty()).then(|| snap.warnings.join("; ")),
    })?;

    Ok(emitted)
}

fn write_processes(
    w: &mut CaseWriter,
    snap: &LiveSnapshot,
    observed: Timestamp,
    inferred: Timestamp,
    image_hashes: &HashMap<String, String>,
) -> Result<()> {
    // Index by PID so a child can find the parent's creation time and build a
    // key that survives PID reuse.
    let keys: std::collections::HashMap<u32, ProcessKey> =
        snap.processes.iter().map(|p| (p.pid, process_key(p))).collect();

    for p in &snap.processes {
        let key = keys[&p.pid];
        let natural = key.natural_key();

        let image_sha256 = p
            .image_path
            .as_deref()
            .and_then(|path| image_hashes.get(&normalize_path(path)))
            .cloned();

        w.upsert_entity(
            &Entity::process(key, &process_label(p)).with_attrs(
                serde_json::json!({
                    "name": p.name,
                    "image_path": p.image_path,
                    "image_sha256": image_sha256,
                    "command_line": p.command_line,
                    "user": p.user,
                    "session_id": p.session_id,
                    "thread_count": p.thread_count,
                    "handle_count": p.handle_count,
                    "wow64": p.is_wow64,
                    "elevated": p.elevated,
                    "module_count": p.modules.len(),
                    "access_error": p.access_error,
                }),
            ),
        )?;

        // The snapshot event sits at the process creation time, not at the
        // collection instant: that is what places a process correctly on the
        // timeline relative to the log records that describe its birth.
        let ts = match p.create_time_filetime {
            Some(ft) => Timestamp::from_filetime(ft),
            None => inferred,
        };

        let hash_note = image_sha256
            .as_deref()
            .map(|h| format!(" sha256:{h}"))
            .unwrap_or_default();
        w.add_event(
            &Event::new(
                ts,
                Source::Live,
                EventKind::ProcessSnapshot,
                format!(
                    "{} (pid {}) running{}{hash_note}",
                    p.name,
                    p.pid,
                    p.user.as_deref().map(|u| format!(" as {u}")).unwrap_or_default()
                ),
            )
            .with_entity(&natural)
            .with_process(p.pid, p.ppid, p.image_path.clone())
            .with_payload(serde_json::json!({
                "command_line": p.command_line,
                "session_id": p.session_id,
                "thread_count": p.thread_count,
                "handle_count": p.handle_count,
                "wow64": p.is_wow64,
                "elevated": p.elevated,
                "access_error": p.access_error,
                "image_sha256": image_sha256,
                "observed_utc_ns": observed.utc_ns,
            })),
        )?;

        if let Some(parent) = p.ppid.and_then(|ppid| keys.get(&ppid)) {
            // A parent whose creation time is later than the child's is a
            // recycled PID, not a real parent. Linking them would produce a
            // plausible-looking but wrong tree, which is worse than an orphan.
            let child_start = key.start_ns;
            let parent_start = parent.start_ns;
            let plausible = parent.is_pid_only()
                || key.is_pid_only()
                || parent_start <= child_start;
            if plausible {
                w.add_edge(&Edge::new(
                    parent.natural_key(),
                    &natural,
                    EdgeKind::ParentOf,
                    Source::Live,
                ))?;
            }
        }

        if let Some(image) = &p.image_path {
            let file_key = normalize_path(image);
            let mut file = Entity::file(image);
            if let Some(h) = image_sha256.as_ref() {
                file = file.with_attrs(serde_json::json!({ "sha256": h, "path": image }));
            }
            w.upsert_entity(&file)?;
            w.add_edge(&Edge::new(
                &natural,
                &file_key,
                EdgeKind::ExecutedImage,
                Source::Live,
            ))?;
        }

        for m in &p.modules {
            let Some(path) = &m.path else { continue };
            let module_key = normalize_path(path);
            w.upsert_entity(&Entity::new(EntityKind::Module, &module_key, &m.name))?;
            w.add_edge(&Edge::new(
                &natural,
                &module_key,
                EdgeKind::LoadedModule,
                Source::Live,
            ))?;

            // The load time is not recoverable from a snapshot, so this is
            // explicitly an observation rather than a load event.
            w.add_event(
                &Event::new(
                    inferred,
                    Source::Live,
                    EventKind::ModuleLoad,
                    format!("{} loaded in {} (pid {})", m.name, p.name, p.pid),
                )
                .with_entity(&natural)
                .with_process(p.pid, p.ppid, p.image_path.clone())
                .with_path(path)
                .with_payload(serde_json::json!({
                    "base": format!("0x{:x}", m.base),
                    "size": m.size,
                })),
            )?;
        }
    }
    Ok(())
}

fn write_endpoints(w: &mut CaseWriter, snap: &LiveSnapshot, inferred: Timestamp) -> Result<()> {
    let keys: std::collections::HashMap<u32, ProcessKey> =
        snap.processes.iter().map(|p| (p.pid, process_key(p))).collect();
    let names: std::collections::HashMap<u32, &LiveProcess> =
        snap.processes.iter().map(|p| (p.pid, p)).collect();

    for e in &snap.endpoints {
        let key = endpoint_key(&e.proto, &e.local, e.remote.as_deref());
        let owner = names.get(&e.pid);
        let listening = e.is_listener();

        // The label carries the direction, not just an address. A bare
        // `0.0.0.0:445` in a relation list is ambiguous about whether the host
        // is serving or reaching out, and that distinction is usually the point.
        let label = match &e.remote {
            Some(r) => format!("{} {} \u{2192} {}", e.proto, e.local, r),
            None => format!("{} {} listening", e.proto, e.local),
        };
        w.upsert_entity(&Entity::new(EntityKind::NetEndpoint, &key, &label))?;

        let mut event = Event::new(
            inferred,
            Source::Live,
            if listening {
                EventKind::NetListen
            } else {
                EventKind::NetConnection
            },
            match &e.remote {
                Some(r) => format!(
                    "{} {} -> {} ({})",
                    e.proto,
                    e.local,
                    r,
                    owner.map(|p| p.name.as_str()).unwrap_or("unknown process")
                ),
                None => format!(
                    "{} listening on {} ({})",
                    e.proto,
                    e.local,
                    owner.map(|p| p.name.as_str()).unwrap_or("unknown process")
                ),
            },
        )
        .with_process(e.pid, None, owner.and_then(|p| p.image_path.clone()))
        .with_payload(serde_json::json!({
            "proto": e.proto,
            "local": e.local,
            "remote": e.remote,
            "state": e.state,
        }));

        if let Some(r) = &e.remote {
            event = event.with_remote(r);
        }
        // The event hangs off the owning process so it lands on that lane in the
        // viewer; the endpoint itself is reachable through the edge.
        if let Some(pk) = keys.get(&e.pid) {
            event = event.with_entity(pk.natural_key());
            w.add_event(&event)?;
            w.add_edge(&Edge::new(
                pk.natural_key(),
                &key,
                EdgeKind::ConnectedTo,
                Source::Live,
            ))?;
        } else {
            // Sockets owned by PID 0 or by a process that exited between the two
            // enumerations still belong in the case.
            event = event.with_entity(&key);
            w.add_event(&event)?;
        }
    }
    Ok(())
}

fn write_services(w: &mut CaseWriter, snap: &LiveSnapshot, inferred: Timestamp) -> Result<()> {
    let keys: std::collections::HashMap<u32, ProcessKey> =
        snap.processes.iter().map(|p| (p.pid, process_key(p))).collect();

    for s in &snap.services {
        let key = format!("svc:{}", s.name.to_ascii_lowercase());
        w.upsert_entity(
            &Entity::new(EntityKind::Service, &key, &s.display_name).with_attrs(
                serde_json::json!({
                    "name": s.name,
                    "state": s.state,
                    "service_type": s.service_type,
                    "start_type": s.start_type,
                    "binary_path": s.binary_path,
                    "account": s.account,
                }),
            ),
        )?;

        let mut event = Event::new(
            inferred,
            Source::Services,
            EventKind::ServiceState,
            format!(
                "service {} is {}{}",
                s.name,
                s.state,
                s.start_type
                    .as_deref()
                    .map(|t| format!(" ({t} start)"))
                    .unwrap_or_default()
            ),
        )
        .with_entity(&key)
        .with_payload(serde_json::json!({
            "display_name": s.display_name,
            "state": s.state,
            "start_type": s.start_type,
            "service_type": s.service_type,
            "account": s.account,
        }));

        if let Some(path) = &s.binary_path {
            event = event.with_path(path);
        }
        if let Some(pid) = s.pid {
            event = event.with_process(pid, None, s.binary_path.clone());
            if let Some(pk) = keys.get(&pid) {
                w.add_edge(&Edge::new(
                    &key,
                    pk.natural_key(),
                    EdgeKind::HostsService,
                    Source::Services,
                ))?;
            }
        }
        w.add_event(&event)?;
    }
    Ok(())
}

fn write_drivers(w: &mut CaseWriter, snap: &LiveSnapshot, inferred: Timestamp) -> Result<()> {
    for d in &snap.drivers {
        let key = match &d.path {
            Some(p) => normalize_path(p),
            None => format!("drv:{}", d.name.to_ascii_lowercase()),
        };
        w.upsert_entity(&Entity::new(EntityKind::Driver, &key, &d.name))?;

        let mut event = Event::new(
            inferred,
            Source::Live,
            EventKind::DriverLoad,
            format!("kernel module {} loaded", d.name),
        )
        .with_entity(&key)
        .with_payload(serde_json::json!({
            "base": format!("0x{:x}", d.base),
            "path": d.path,
        }));
        if let Some(p) = &d.path {
            event = event.with_path(p);
        }
        w.add_event(&event)?;
    }
    Ok(())
}

fn write_autoruns(w: &mut CaseWriter, snap: &LiveSnapshot, inferred: Timestamp) -> Result<()> {
    for a in &snap.autoruns {
        let key = format!("reg:{}\\{}", a.full_key().to_ascii_lowercase(), a.value_name);
        w.upsert_entity(&Entity::new(EntityKind::RegistryKey, &key, &a.value_name))?;

        w.add_event(
            &Event::new(
                inferred,
                Source::Registry,
                EventKind::AutostartEntry,
                format!("{} runs {}", a.value_name, a.value),
            )
            .with_entity(&key)
            .with_path(&a.value)
            .with_payload(serde_json::json!({
                "hive": a.hive,
                "key": a.key,
                "value_name": a.value_name,
                "value": a.value,
            })),
        )?;
    }
    Ok(())
}

/// Convert the live host description into the model's host record.
pub fn host_info(h: &tpv_live_win::LiveHostInfo) -> tpv_model::HostInfo {
    tpv_model::HostInfo {
        hostname: h.hostname.clone(),
        os_name: h.os_name.clone(),
        os_version: h.os_version.clone(),
        architecture: h.architecture.clone(),
        domain: h.domain.clone(),
        machine_id: h.machine_id.clone(),
        timezone_name: h.timezone_name.clone(),
        utc_offset_minutes: h.utc_offset_minutes,
        boot_time: h.boot_time_filetime.map(Timestamp::from_filetime),
    }
}

/// The reference clock, taken from the same capture as the host description.
pub fn reference_clock(h: &tpv_live_win::LiveHostInfo) -> tpv_model::ReferenceClock {
    tpv_model::ReferenceClock {
        host_utc: Timestamp::from_filetime(h.now_filetime),
        monotonic_uptime_ms: Some(h.uptime_ms),
    }
}

/// Collection instant, used for everything the snapshot observed but did not time.
pub fn observed_at(h: &tpv_live_win::LiveHostInfo) -> Timestamp {
    let mut ts = Timestamp::from_filetime(h.now_filetime);
    // The wall clock is only trustworthy to the precision Windows actually
    // maintains for it, and claiming 100 ns here would imply the collection was
    // instantaneous.
    ts.precision = TsPrecision::Millisecond;
    ts.tz_source = TzSource::NativeUtc;
    ts
}
