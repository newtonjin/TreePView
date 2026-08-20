//! The IPC surface the frontend talks to.
//!
//! Every command is a query that returns something already sized for display.
//! Nothing here streams a full table to JavaScript: filtering, aggregation and
//! binning all happen against SQLite indexes in [`tpv_format`], and the frontend
//! receives at most a page of rows or a few hundred bin counts. That is what
//! keeps a case with millions of events responsive, and it is why the shape of
//! these return types matters as much as their contents.

use std::sync::Mutex;

use serde::Serialize;
use tauri::State;
use tpv_format::{
    CaseMeta, CaseReader, Counts, EntityRow, EventFilter, EventRow, LaneSeries, ProcessNode,
    RelatedEntity, TimeBin,
};
use tpv_model::{Finding, ManifestEntry};

use crate::error::{Result, ViewerError};

#[derive(Default)]
pub struct CaseState(pub Mutex<Option<CaseReader>>);

impl CaseState {
    /// Run `f` against the open case.
    ///
    /// Takes a closure rather than returning a guard so the lock is never held
    /// across an await or a second command, which would let one slow query
    /// block the whole UI.
    fn with<T>(&self, f: impl FnOnce(&CaseReader) -> Result<T>) -> Result<T> {
        let guard = self.0.lock().expect("case lock poisoned");
        f(guard.as_ref().ok_or(ViewerError::NoCaseOpen)?)
    }
}

/// Everything the shell needs to render itself right after a case opens.
///
/// Bundled into one response deliberately: these are all cheap, they are all
/// needed at once, and six separate round trips would show the analyst a window
/// that fills in piecemeal.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseOverview {
    pub path: String,
    pub meta: CaseMeta,
    pub counts: Counts,
    /// `None` when every event has a suspect timestamp, or when there are none.
    pub span: Option<(i64, i64)>,
    pub sources: Vec<Facet>,
    pub kinds: Vec<Facet>,
    /// Artifacts that failed to acquire. Surfaced separately from the manifest
    /// because an analyst has to know what is missing before concluding that an
    /// absence in the timeline means the activity did not happen.
    pub gaps: Vec<Gap>,
}

#[derive(Serialize)]
pub struct Facet {
    pub value: String,
    pub count: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Gap {
    pub source_path: String,
    pub method: String,
    pub error: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventPage {
    pub rows: Vec<EventRow>,
    /// Total matching the filter, not just this page, so the UI can say how much
    /// it is not showing.
    pub total: i64,
    pub offset: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventDetail {
    pub event: EventRow,
    /// The full source record, decompressed on demand.
    pub payload: Option<serde_json::Value>,
    pub entity: Option<EntityRow>,
    pub related: Vec<RelatedEntity>,
    /// How this event's source was acquired, so provenance is one click away.
    pub provenance: Option<ManifestEntry>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityDetail {
    pub entity: EntityRow,
    pub related: Vec<RelatedEntity>,
    pub recent: Vec<EventRow>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyReport {
    pub finalized: bool,
    pub digest_matches: bool,
    pub sealed_digest: Option<String>,
}

#[tauri::command]
pub fn open_case(path: String, state: State<'_, CaseState>) -> Result<CaseOverview> {
    let reader = crate::open::open_any(std::path::Path::new(&path))?;
    let overview = build_overview(&reader)?;
    *state.0.lock().expect("case lock poisoned") = Some(reader);
    Ok(overview)
}

#[tauri::command]
pub fn close_case(state: State<'_, CaseState>) {
    *state.0.lock().expect("case lock poisoned") = None;
}

#[tauri::command]
pub fn overview(state: State<'_, CaseState>) -> Result<CaseOverview> {
    state.with(build_overview)
}

fn build_overview(r: &CaseReader) -> Result<CaseOverview> {
    let facets = |rows: Vec<(String, i64)>| {
        rows.into_iter()
            .map(|(value, count)| Facet { value, count })
            .collect()
    };

    Ok(CaseOverview {
        path: r.path().display().to_string(),
        meta: r.meta()?,
        counts: r.counts()?,
        span: r.time_span()?,
        sources: facets(r.source_counts()?),
        kinds: facets(r.kind_counts()?),
        gaps: r
            .manifest()?
            .into_iter()
            .filter_map(|m| {
                m.error.map(|error| Gap {
                    source_path: m.source_path,
                    method: m.method.as_str().into(),
                    error,
                })
            })
            .collect(),
    })
}

#[tauri::command]
pub fn process_tree(state: State<'_, CaseState>) -> Result<Vec<ProcessNode>> {
    state.with(|r| Ok(r.process_tree()?))
}

#[tauri::command]
pub fn query_events(
    filter: EventFilter,
    limit: u32,
    offset: u32,
    state: State<'_, CaseState>,
) -> Result<EventPage> {
    // Capped so a mis-typed limit from the frontend cannot try to materialize a
    // million rows into JSON and hang the window.
    let limit = limit.clamp(1, 5_000);
    state.with(|r| {
        Ok(EventPage {
            rows: r.events(&filter, limit, offset)?,
            total: r.count_events(&filter)?,
            offset,
        })
    })
}

#[tauri::command]
pub fn histogram(
    filter: EventFilter,
    from_ns: i64,
    to_ns: i64,
    bins: u32,
    state: State<'_, CaseState>,
) -> Result<Vec<TimeBin>> {
    let bins = bins.clamp(1, 4_000);
    state.with(|r| Ok(r.bin_events(&filter, from_ns, to_ns, bins)?))
}

#[tauri::command]
pub fn histogram_lanes(
    filter: EventFilter,
    from_ns: i64,
    to_ns: i64,
    bins: u32,
    state: State<'_, CaseState>,
) -> Result<Vec<LaneSeries>> {
    let bins = bins.clamp(1, 4_000);
    state.with(|r| Ok(r.bin_lanes(&filter, from_ns, to_ns, bins)?))
}

#[tauri::command]
pub fn inspect_event(id: i64, state: State<'_, CaseState>) -> Result<EventDetail> {
    state.with(|r| {
        let event = r.event(id)?.ok_or(ViewerError::NoSuchEvent(id))?;
        let entity = match &event.entity_key {
            Some(k) => r.entity(k)?,
            None => None,
        };
        let related = match &event.entity_key {
            Some(k) => r.related(k, 200)?,
            None => Vec::new(),
        };
        // Matching provenance by source name keeps the manifest independent of
        // event ids, so findings and re-parsing cannot invalidate the link.
        let provenance = r
            .manifest()?
            .into_iter()
            .find(|m| provenance_matches(m, &event));

        Ok(EventDetail {
            payload: r.payload(id)?,
            event,
            entity,
            related,
            provenance,
        })
    })
}

/// Whether a manifest entry is the acquisition that produced this event.
fn provenance_matches(m: &ManifestEntry, e: &EventRow) -> bool {
    match &e.path {
        Some(p) => m.source_path.eq_ignore_ascii_case(p),
        None => false,
    }
}

#[tauri::command]
pub fn inspect_entity(key: String, state: State<'_, CaseState>) -> Result<EntityDetail> {
    state.with(|r| {
        let entity = r
            .entity(&key)?
            .ok_or_else(|| ViewerError::NoSuchEntity(key.clone()))?;
        Ok(EntityDetail {
            related: r.related(&key, 500)?,
            recent: r.events(
                &EventFilter {
                    entity_key: Some(key.clone()),
                    ..Default::default()
                },
                200,
                0,
            )?,
            entity,
        })
    })
}

#[tauri::command]
pub fn manifest(state: State<'_, CaseState>) -> Result<Vec<ManifestEntry>> {
    state.with(|r| Ok(r.manifest()?))
}

#[tauri::command]
pub fn findings(state: State<'_, CaseState>) -> Result<Vec<Finding>> {
    state.with(|r| Ok(r.findings()?))
}

#[tauri::command]
pub fn export_events(
    path: String,
    format: String,
    filter: EventFilter,
    state: State<'_, CaseState>,
) -> Result<()> {
    const CAP: u32 = 20_000;
    state.with(|r| {
        let total = r.count_events(&filter)?;
        let rows = r.events(&filter, CAP, 0)?;
        let body = match format.as_str() {
            "csv" => tpv_format::events_csv(&rows),
            "jsonl" => tpv_format::events_jsonl(&rows).map_err(tpv_format::FormatError::from)?,
            "md" | "markdown" => {
                let sample_n = rows.len().min(40);
                tpv_format::case_markdown(
                    &r.meta()?,
                    &r.counts()?,
                    &r.manifest()?,
                    &r.findings()?,
                    &rows[..sample_n],
                    total,
                )
            }
            other => {
                return Err(ViewerError::UnsupportedFile {
                    path: std::path::PathBuf::from(&path),
                    reason: format!("unknown export format {other}"),
                });
            }
        };
        std::fs::write(&path, body)?;
        Ok(())
    })
}

#[tauri::command]
pub fn verify(state: State<'_, CaseState>) -> Result<VerifyReport> {
    state.with(|r| {
        let meta = r.meta()?;
        Ok(VerifyReport {
            digest_matches: meta.finalized && r.verify_content_digest()?,
            finalized: meta.finalized,
            sealed_digest: meta.content_digest,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpv_model::{
        AccessMethod, CaseId, CollectionProfile, Custody, Entity, Event, EventKind, HostInfo,
        ManifestEntry, ReferenceClock, Source, Timestamp, TsPrecision, TzSource,
    };

    fn ts(ns: i64) -> Timestamp {
        Timestamp::new(ns, TsPrecision::Nanosecond, TzSource::NativeUtc)
    }

    /// A case containing one successful acquisition and one failed one.
    fn case(path: &std::path::Path) {
        let mut w = tpv_format::CaseWriter::create(
            path,
            tpv_format::CaseInit {
                case_id: CaseId::generate(),
                tool_version: "tpv-test/0.1.0".into(),
                host: HostInfo {
                    hostname: "TARGET".into(),
                    os_name: "Windows".into(),
                    os_version: "11".into(),
                    architecture: "x86_64".into(),
                    domain: None,
                    machine_id: None,
                    timezone_name: None,
                    utc_offset_minutes: None,
                    boot_time: None,
                },
                clock: ReferenceClock {
                    host_utc: ts(1_000),
                    monotonic_uptime_ms: None,
                },
                profile: CollectionProfile::default(),
            },
        )
        .unwrap();

        w.upsert_entity(&Entity::file(r"C:\Users\Public\evil.exe"))
            .unwrap();
        w.add_event(
            &Event::new(
                ts(5_000),
                Source::Prefetch,
                EventKind::ExecutionEvidence,
                "EVIL.EXE ran",
            )
            .with_path(r"C:\Windows\Prefetch\EVIL.EXE-1234ABCD.pf"),
        )
        .unwrap();
        w.add_event(&Event::new(
            ts(6_000),
            Source::Live,
            EventKind::ProcessSnapshot,
            "a live observation with no file behind it",
        ))
        .unwrap();

        w.add_manifest(&ManifestEntry {
            source_path: r"C:\Windows\Prefetch\EVIL.EXE-1234ABCD.pf".into(),
            method: AccessMethod::RawVolume,
            size_bytes: 27_411,
            sha256: Some("a".repeat(64)),
            started: ts(2_000),
            finished: ts(2_100),
            events_emitted: 1,
            error: None,
        })
        .unwrap();
        w.add_manifest(&ManifestEntry {
            source_path: r"C:\Windows\System32\config\SYSTEM".into(),
            method: AccessMethod::VolumeShadowCopy,
            size_bytes: 0,
            sha256: None,
            started: ts(3_000),
            finished: ts(3_100),
            events_emitted: 0,
            error: Some("no shadow copies present".into()),
        })
        .unwrap();

        w.finish(Custody {
            collector_version: "tpv-test/0.1.0".into(),
            collector_pid: 1,
            collector_image: "tpv.exe".into(),
            collector_sha256: None,
            command_line: "tpv collect".into(),
            started: ts(1_000),
            finished: ts(9_000),
            run_as_user: "SYSTEM".into(),
            elevated: true,
            files_written: vec![],
            warnings: vec![],
        })
        .unwrap();
    }

    #[test]
    fn the_overview_separates_failed_acquisitions_from_successful_ones() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("case.tpv");
        case(&path);

        let r = CaseReader::open(&path).unwrap();
        let o = build_overview(&r).unwrap();

        assert_eq!(o.counts.events, 2);
        assert_eq!(o.meta.host.hostname, "TARGET");

        // Only the failure is a gap. Surfacing the successful acquisition here
        // too would train the analyst to ignore the list.
        assert_eq!(o.gaps.len(), 1);
        assert!(o.gaps[0].source_path.ends_with("SYSTEM"));
        assert_eq!(o.gaps[0].method, "vss");
        assert!(o.gaps[0].error.contains("no shadow copies"));

        let sources: Vec<&str> = o.sources.iter().map(|f| f.value.as_str()).collect();
        assert!(sources.contains(&"prefetch"));
        assert!(sources.contains(&"live"));
    }

    #[test]
    fn an_event_links_to_the_artifact_it_was_parsed_from() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("case.tpv");
        case(&path);

        let r = CaseReader::open(&path).unwrap();
        let manifest = r.manifest().unwrap();

        let parsed = r
            .events(
                &EventFilter {
                    sources: vec![tpv_model::Source::Prefetch],
                    ..Default::default()
                },
                1,
                0,
            )
            .unwrap()
            .remove(0);
        let matched = manifest.iter().find(|m| provenance_matches(m, &parsed));
        assert_eq!(
            matched.map(|m| m.sha256.clone()),
            Some(Some("a".repeat(64))),
            "a prefetch event must trace back to the .pf it came from"
        );

        // A live observation has no file behind it, and claiming one would be a
        // false provenance chain.
        let live = r
            .events(
                &EventFilter {
                    sources: vec![tpv_model::Source::Live],
                    ..Default::default()
                },
                1,
                0,
            )
            .unwrap()
            .remove(0);
        assert!(manifest.iter().all(|m| !provenance_matches(m, &live)));
    }

    #[test]
    fn a_query_without_an_open_case_fails_rather_than_returning_nothing() {
        let state = CaseState::default();
        // An empty result would read as "this case contains no events", which is
        // a different and much more dangerous statement than "no case is open".
        let err = state.with(|r| Ok(r.counts()?)).unwrap_err();
        assert!(matches!(err, ViewerError::NoCaseOpen));
    }
}
