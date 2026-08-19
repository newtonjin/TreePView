use std::io::{Read, Seek, SeekFrom};

use tpv_model::{
    entity::ProcessKey, host::MemoryMode, AccessMethod, CaseId, CollectionProfile, Confidence,
    Custody, Edge, EdgeKind, Entity, EntityKind, Event, EventKind, Finding, HostInfo, ManifestEntry,
    ReferenceClock, Severity, Source, Timestamp, TsPrecision, TzSource,
};

use crate::{CaseInit, CaseReader, CaseWriter, EventFilter, FormatError};

fn ts(ns: i64) -> Timestamp {
    Timestamp::new(ns, TsPrecision::Nanosecond, TzSource::NativeUtc)
}

fn init() -> CaseInit {
    CaseInit {
        case_id: CaseId::generate(),
        tool_version: "tpv-test/0.1.0".into(),
        host: HostInfo {
            hostname: "GELADEIRA".into(),
            os_name: "Windows".into(),
            os_version: "11 (26200)".into(),
            architecture: "x86_64".into(),
            domain: None,
            machine_id: Some("machine-guid".into()),
            timezone_name: Some("America/Sao_Paulo".into()),
            utc_offset_minutes: Some(180),
            boot_time: Some(ts(1_000)),
        },
        clock: ReferenceClock {
            host_utc: ts(10_000),
            monotonic_uptime_ms: Some(42_000),
        },
        profile: CollectionProfile {
            memory: MemoryMode::RegionsOnly,
            ..Default::default()
        },
    }
}

fn custody() -> Custody {
    Custody {
        collector_version: "tpv-test/0.1.0".into(),
        collector_pid: 4242,
        collector_image: r"E:\tools\tpv.exe".into(),
        collector_sha256: Some("f".repeat(64)),
        command_line: "tpv collect --out E:\\case.tpv".into(),
        started: ts(10_000),
        finished: ts(90_000),
        run_as_user: "GELADEIRA\\newto".into(),
        elevated: true,
        files_written: vec![r"E:\case.tpv".into()],
        warnings: vec![],
    }
}

/// A small case with a three-process tree, used by most tests.
fn build_case(path: &std::path::Path) -> crate::CaseSummary {
    let mut w = CaseWriter::create(path, init()).unwrap();

    let root = ProcessKey::new(4, 1_000);
    let mid = ProcessKey::new(800, 2_000);
    let leaf = ProcessKey::new(1337, 3_000);

    w.upsert_entity(&Entity::process(root, "System")).unwrap();
    w.upsert_entity(&Entity::process(mid, "services.exe")).unwrap();
    w.upsert_entity(
        &Entity::process(leaf, "evil.exe")
            .with_attrs(serde_json::json!({"cmdline": "evil.exe --beacon"})),
    )
    .unwrap();

    w.add_edge(&Edge::new(
        root.natural_key(),
        mid.natural_key(),
        EdgeKind::ParentOf,
        Source::Live,
    ))
    .unwrap();
    w.add_edge(&Edge::new(
        mid.natural_key(),
        leaf.natural_key(),
        EdgeKind::ParentOf,
        Source::Live,
    ))
    .unwrap();

    for (i, key) in [root, mid, leaf].iter().enumerate() {
        w.add_event(
            &Event::new(
                ts(1_000 + i as i64 * 1_000),
                Source::Live,
                EventKind::ProcessSnapshot,
                format!("process {} alive", key.pid),
            )
            .with_entity(key.natural_key())
            .with_process(key.pid, None, Some(format!("C:\\Windows\\proc{}.exe", key.pid))),
        )
        .unwrap();
    }

    w.add_event(
        &Event::new(
            ts(5_000),
            Source::Live,
            EventKind::NetConnection,
            "outbound to 203.0.113.7:443",
        )
        .with_entity(leaf.natural_key())
        .with_process(leaf.pid, Some(mid.pid), Some("C:\\Users\\Public\\evil.exe".into()))
        .with_remote("203.0.113.7:443")
        .with_payload(serde_json::json!({"proto": "tcp", "state": "established"})),
    )
    .unwrap();

    w.add_event(
        &Event::new(
            ts(6_000),
            Source::Prefetch,
            EventKind::ExecutionEvidence,
            "EVIL.EXE ran 3 times",
        )
        .with_path(r"C:\Users\Public\evil.exe")
        .with_payload(serde_json::json!({"run_count": 3})),
    )
    .unwrap();

    // Deliberately identical payload to the previous event, to exercise dedup.
    w.add_event(
        &Event::new(
            ts(6_500),
            Source::Prefetch,
            EventKind::ExecutionEvidence,
            "EVIL.EXE seen again",
        )
        .with_payload(serde_json::json!({"run_count": 3})),
    )
    .unwrap();

    // A timestomped record: FILETIME zero, which clamps and flags.
    w.add_event(&Event::new(
        Timestamp::from_filetime(0),
        Source::Mft,
        EventKind::FileMetadata,
        "$SI creation time is zero",
    ))
    .unwrap();

    w.add_manifest(&ManifestEntry {
        source_path: r"C:\Windows\Prefetch\EVIL.EXE-1234ABCD.pf".into(),
        method: AccessMethod::RawVolume,
        size_bytes: 27_411,
        sha256: Some("a".repeat(64)),
        started: ts(20_000),
        finished: ts(21_000),
        events_emitted: 2,
        error: None,
    })
    .unwrap();

    // A failed acquisition is recorded, not dropped.
    w.add_manifest(&ManifestEntry {
        source_path: r"C:\Windows\System32\config\SYSTEM".into(),
        method: AccessMethod::VolumeShadowCopy,
        size_bytes: 0,
        sha256: None,
        started: ts(22_000),
        finished: ts(22_100),
        events_emitted: 0,
        error: Some("no shadow copies present".into()),
    })
    .unwrap();

    let payload: Vec<u8> = (0..(10 * 1024 * 1024u32)).map(|i| (i % 251) as u8).collect();
    w.add_blob(
        "minidump/1337-evil.exe",
        "minidump",
        Some(&leaf.natural_key()),
        &mut &payload[..],
    )
    .unwrap();

    w.finish(custody()).unwrap()
}

#[test]
fn case_roundtrips_through_the_container() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    let summary = build_case(&path);

    assert_eq!(summary.events, 7);
    assert_eq!(summary.blobs, 1);
    assert_eq!(summary.manifest_entries, 2);
    assert!(summary.file_size > 0);
    assert_eq!(summary.file_digest.len(), 64);
    assert!(path.with_extension("tpv.sha256").exists());

    let r = CaseReader::open(&path).unwrap();
    let meta = r.meta().unwrap();
    assert_eq!(meta.host.hostname, "GELADEIRA");
    assert_eq!(meta.host.utc_offset_minutes, Some(180));
    assert!(meta.finalized);
    assert_eq!(meta.custody.unwrap().collector_pid, 4242);

    let counts = r.counts().unwrap();
    assert_eq!(counts.events, 7);
    assert_eq!(counts.entities, 3);
    assert_eq!(counts.edges, 2);
}

#[test]
fn identical_payloads_are_stored_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    build_case(&path);

    let r = CaseReader::open(&path).unwrap();
    // Three events carry a payload, but two of them are byte-identical.
    let payload_rows: i64 = r
        .events(&EventFilter::default(), 1000, 0)
        .unwrap()
        .iter()
        .filter(|e| e.has_payload)
        .count() as i64;
    assert_eq!(payload_rows, 3);

    let distinct: i64 = {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.query_row("SELECT COUNT(*) FROM payloads", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(distinct, 2, "identical payloads should collapse to one row");
}

#[test]
fn blob_supports_random_access_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    build_case(&path);

    let r = CaseReader::open(&path).unwrap();
    let blobs = r.blobs().unwrap();
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].raw_len, 10 * 1024 * 1024);
    // 10 MiB at a 4 MiB chunk size is three chunks, the last one short.
    assert_eq!(blobs[0].chunk_count, 3);

    let mut reader = r.blob_reader(blobs[0].id).unwrap();

    // A read that starts inside the third chunk must not require the first two.
    let offset = 9 * 1024 * 1024 + 7;
    reader.seek(SeekFrom::Start(offset)).unwrap();
    let mut buf = [0u8; 16];
    reader.read_exact(&mut buf).unwrap();
    for (i, b) in buf.iter().enumerate() {
        assert_eq!(*b, ((offset as usize + i) % 251) as u8);
    }

    // Reads spanning a chunk boundary must stitch correctly.
    reader.seek(SeekFrom::Start(4 * 1024 * 1024 - 4)).unwrap();
    let mut span = [0u8; 8];
    reader.read_exact(&mut span).unwrap();
    for (i, b) in span.iter().enumerate() {
        assert_eq!(*b, ((4 * 1024 * 1024 - 4 + i) % 251) as u8);
    }

    let full = reader.read_all_verified().unwrap();
    assert_eq!(full.len(), 10 * 1024 * 1024);

    // Seeking past the end yields no bytes rather than an error, matching a file.
    reader.seek(SeekFrom::End(64)).unwrap();
    let mut tail = [0u8; 4];
    assert_eq!(reader.read(&mut tail).unwrap(), 0);
}

#[test]
fn process_tree_nests_by_parent_edges() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    build_case(&path);

    let r = CaseReader::open(&path).unwrap();
    let roots = r.process_tree().unwrap();

    assert_eq!(roots.len(), 1, "only System has no parent");
    let system = &roots[0];
    assert_eq!(system.pid, Some(4));
    assert_eq!(system.children.len(), 1);

    let services = &system.children[0];
    assert_eq!(services.pid, Some(800));
    assert_eq!(services.children.len(), 1);

    let evil = &services.children[0];
    assert_eq!(evil.pid, Some(1337));
    let started = evil.started.as_ref().expect("a start time");
    assert_eq!(started.ns, 3_000, "start time recovered from the key");
    assert!(started.exact);
    assert!(evil.children.is_empty());
    // Snapshot plus the network connection.
    assert_eq!(evil.event_count, 2);
}

#[test]
fn filters_narrow_by_pid_source_and_network() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    build_case(&path);
    let r = CaseReader::open(&path).unwrap();

    let by_pid = EventFilter {
        pids: vec![1337],
        ..Default::default()
    };
    assert_eq!(r.count_events(&by_pid).unwrap(), 2);

    let by_source = EventFilter {
        sources: vec![Source::Prefetch],
        ..Default::default()
    };
    assert_eq!(r.count_events(&by_source).unwrap(), 2);

    let network = EventFilter {
        network_only: true,
        ..Default::default()
    };
    let rows = r.events(&network, 10, 0).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].remote.as_deref(), Some("203.0.113.7:443"));

    let by_kind = EventFilter {
        kinds: vec![EventKind::ExecutionEvidence],
        ..Default::default()
    };
    assert_eq!(r.count_events(&by_kind).unwrap(), 2);
}

#[test]
fn column_filters_and_logs_only_narrow_independently_of_full_text() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    let mut w = CaseWriter::create(&path, init()).unwrap();
    let key = ProcessKey::new(1337, 3_000);
    w.upsert_entity(&Entity::process(key, "evil.exe")).unwrap();
    w.add_event(
        &Event::new(ts(3_000), Source::Live, EventKind::ProcessSnapshot, "evil.exe alive")
            .with_entity(key.natural_key())
            .with_process(1337, Some(800), Some(r"C:\Users\Public\evil.exe".into()))
            .with_user(r"CORP\victim"),
    )
    .unwrap();
    w.add_event(
        &Event::new(ts(4_000), Source::Evtx, EventKind::ProcessStart, "cmd.exe (pid 1337) started")
            .with_process(1337, Some(800), Some(r"C:\Windows\System32\cmd.exe".into()))
            .with_path("Security")
            .with_log_id(4688)
            .with_user(r"CORP\victim"),
    )
    .unwrap();
    w.add_event(
        &Event::new(ts(5_000), Source::Evtx, EventKind::LogonSession, "logon CORP\\alice type 10")
            .with_path("Security")
            .with_log_id(4624)
            .with_user(r"CORP\alice")
            .with_remote("10.0.0.8"),
    )
    .unwrap();
    w.finish(custody()).unwrap();
    let r = CaseReader::open(&path).unwrap();

    assert_eq!(
        r.count_events(&EventFilter { logs_only: true, ..Default::default() })
            .unwrap(),
        2
    );
    assert_eq!(
        r.count_events(&EventFilter {
            path_contains: Some("Security".into()),
            ..Default::default()
        })
        .unwrap(),
        2
    );
    assert_eq!(
        r.count_events(&EventFilter {
            user_contains: Some(r"CORP\alice".into()),
            ..Default::default()
        })
        .unwrap(),
        1
    );
    assert_eq!(
        r.count_events(&EventFilter {
            remote_contains: Some("10.0.0.8".into()),
            ..Default::default()
        })
        .unwrap(),
        1
    );
    assert_eq!(
        r.count_events(&EventFilter {
            kind_contains: Some("logon".into()),
            ..Default::default()
        })
        .unwrap(),
        1
    );
    assert_eq!(
        r.count_events(&EventFilter {
            pid_contains: Some("133".into()),
            ..Default::default()
        })
        .unwrap(),
        2
    );
    assert_eq!(
        r.count_events(&EventFilter {
            log_ids: vec![4688],
            ..Default::default()
        })
        .unwrap(),
        1
    );
    assert_eq!(
        r.count_events(&EventFilter {
            log_id_contains: Some("46".into()),
            ..Default::default()
        })
        .unwrap(),
        2
    );
    // Pinning the live process also returns the EVTX start that shares its PID.
    assert_eq!(
        r.count_events(&EventFilter {
            entity_key: Some(key.natural_key()),
            ..Default::default()
        })
        .unwrap(),
        2
    );

    assert_eq!(
        r.count_events(&EventFilter {
            text: Some("id:4688".into()),
            ..Default::default()
        })
        .unwrap(),
        1
    );
    assert_eq!(
        r.count_events(&EventFilter {
            text: Some("4624".into()),
            ..Default::default()
        })
        .unwrap(),
        1
    );
    assert_eq!(
        r.count_events(&EventFilter {
            text: Some("user:alice".into()),
            ..Default::default()
        })
        .unwrap(),
        1
    );
    assert_eq!(
        r.count_events(&EventFilter {
            text: Some("channel:Security".into()),
            ..Default::default()
        })
        .unwrap(),
        2
    );
    assert_eq!(
        r.events(&EventFilter { log_ids: vec![4688], ..Default::default() }, 10, 0)
            .unwrap()[0]
            .log_id,
        Some(4688)
    );
}

#[test]
fn suspect_timestamps_are_findable_and_excluded_from_the_axis() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    build_case(&path);
    let r = CaseReader::open(&path).unwrap();

    let suspect = EventFilter {
        suspect_time_only: true,
        ..Default::default()
    };
    let rows = r.events(&suspect, 10, 0).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].ts.is_suspect());

    // The clamped row must not stretch the timeline axis to the i64 floor.
    let (lo, hi) = r.time_span().unwrap().unwrap();
    assert_eq!(lo, 1_000);
    assert_eq!(hi, 6_500);
}

#[test]
fn full_text_search_matches_paths_and_summaries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    build_case(&path);
    let r = CaseReader::open(&path).unwrap();

    let f = EventFilter {
        text: Some("evil.exe".into()),
        ..Default::default()
    };
    assert!(
        r.count_events(&f).unwrap() >= 2,
        "the tokenizer must not split on path separators"
    );

    let miss = EventFilter {
        text: Some("nonexistentneedle".into()),
        ..Default::default()
    };
    assert_eq!(r.count_events(&miss).unwrap(), 0);

    // A full Windows path is the most common thing an analyst pastes in, and
    // every character in it is FTS5 punctuation.
    let by_path = EventFilter {
        text: Some(r"C:\Users\Public\evil.exe".into()),
        ..Default::default()
    };
    assert!(r.count_events(&by_path).unwrap() >= 1);

    // So is an address:port pair.
    let by_peer = EventFilter {
        text: Some("203.0.113.7".into()),
        ..Default::default()
    };
    assert_eq!(r.count_events(&by_peer).unwrap(), 1);

    // Two terms narrow rather than widen.
    let both = EventFilter {
        text: Some("evil.exe ran".into()),
        ..Default::default()
    };
    assert_eq!(r.count_events(&both).unwrap(), 1);

    // Prefix search survives quoting.
    let prefix = EventFilter {
        text: Some("outbou*".into()),
        ..Default::default()
    };
    assert_eq!(r.count_events(&prefix).unwrap(), 1);

    // An empty query must not silently match nothing.
    let blank = EventFilter {
        text: Some("   ".into()),
        ..Default::default()
    };
    assert_eq!(r.count_events(&blank).unwrap(), 7);
}

#[test]
fn binning_covers_the_range_and_preserves_totals() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    build_case(&path);
    let r = CaseReader::open(&path).unwrap();

    let bins = r.bin_events(&EventFilter::default(), 0, 10_000, 10).unwrap();
    assert_eq!(bins.len(), 10);
    assert_eq!(bins[0].start_ns, 0);
    assert_eq!(bins[9].end_ns, 10_000);

    // Six of the seven events fall inside the range; the clamped one does not.
    let total: i64 = bins.iter().map(|b| b.count).sum();
    assert_eq!(total, 6);

    // Binning must not divide by zero on a degenerate range.
    let degenerate = r.bin_events(&EventFilter::default(), 5_000, 5_000, 4).unwrap();
    assert_eq!(degenerate.len(), 4);
}

#[test]
fn findings_are_replaceable_and_carry_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    build_case(&path);

    let event_id = {
        let r = CaseReader::open(&path).unwrap();
        let net = EventFilter {
            network_only: true,
            ..Default::default()
        };
        r.events(&net, 1, 0).unwrap()[0].id
    };

    let mut rw = CaseReader::open_for_findings(&path).unwrap();
    let finding = Finding::new(
        "net.suspicious_peer",
        Severity::High,
        Confidence::Medium,
        "Outbound TLS to an unfamiliar host",
        "evil.exe connected to 203.0.113.7:443",
        vec![event_id],
    )
    .about(ProcessKey::new(1337, 3_000).natural_key());
    rw.replace_findings(&[finding], 99_000).unwrap();

    let r = CaseReader::open(&path).unwrap();
    let found = r.findings().unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].evidence, vec![event_id]);
    assert!(found[0].is_supported());

    // The severity must decorate the owning node in the tree.
    let roots = r.process_tree().unwrap();
    let evil = &roots[0].children[0].children[0];
    assert_eq!(evil.max_severity, Some(Severity::High));

    // Replacing wholesale must not leave the previous set behind.
    let mut rw = CaseReader::open_for_findings(&path).unwrap();
    rw.replace_findings(&[], 100_000).unwrap();
    assert!(CaseReader::open(&path).unwrap().findings().unwrap().is_empty());
}

#[test]
fn min_severity_filter_selects_evidenced_events() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    build_case(&path);

    let event_id = {
        let r = CaseReader::open(&path).unwrap();
        r.events(
            &EventFilter {
                network_only: true,
                ..Default::default()
            },
            1,
            0,
        )
        .unwrap()[0]
            .id
    };

    let mut rw = CaseReader::open_for_findings(&path).unwrap();
    rw.replace_findings(
        &[Finding::new(
            "r",
            Severity::Medium,
            Confidence::High,
            "t",
            "d",
            vec![event_id],
        )],
        1,
    )
    .unwrap();

    let r = CaseReader::open(&path).unwrap();
    let high = EventFilter {
        min_severity: Some(Severity::High),
        ..Default::default()
    };
    assert_eq!(r.count_events(&high).unwrap(), 0);

    let medium = EventFilter {
        min_severity: Some(Severity::Medium),
        ..Default::default()
    };
    assert_eq!(r.count_events(&medium).unwrap(), 1);
}

#[test]
fn manifest_records_failures_as_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    build_case(&path);

    let r = CaseReader::open(&path).unwrap();
    let manifest = r.manifest().unwrap();
    assert_eq!(manifest.len(), 2);

    let failed = manifest.iter().find(|m| m.error.is_some()).unwrap();
    assert!(!failed.is_complete());
    assert_eq!(failed.method, AccessMethod::VolumeShadowCopy);
    assert!(!failed.method.perturbs_source());

    let ok = manifest.iter().find(|m| m.error.is_none()).unwrap();
    assert!(ok.is_complete());
    assert_eq!(ok.method, AccessMethod::RawVolume);
}

#[test]
fn content_digest_detects_tampering_with_stored_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    build_case(&path);

    assert!(CaseReader::open(&path).unwrap().verify_content_digest().unwrap());

    // Alter a recorded artifact hash the way someone hiding a swap would.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE manifest SET sha256 = ?1 WHERE sha256 IS NOT NULL", ["b".repeat(64)])
            .unwrap();
    }

    assert!(
        !CaseReader::open(&path).unwrap().verify_content_digest().unwrap(),
        "editing an artifact hash must break the sealed digest"
    );
}

#[test]
fn entity_upsert_promotes_placeholders() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    let mut w = CaseWriter::create(&path, init()).unwrap();

    let parent = ProcessKey::new(100, 1);
    let child = ProcessKey::new(200, 2);

    // The edge names both processes before either has been described.
    w.add_edge(&Edge::new(
        parent.natural_key(),
        child.natural_key(),
        EdgeKind::ParentOf,
        Source::Live,
    ))
    .unwrap();

    w.upsert_entity(&Entity::process(parent, "explorer.exe")).unwrap();
    w.upsert_entity(&Entity::process(child, "cmd.exe")).unwrap();
    w.finish(custody()).unwrap();

    let r = CaseReader::open(&path).unwrap();
    assert_eq!(r.counts().unwrap().entities, 2, "no duplicate placeholder rows");

    let roots = r.process_tree().unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].label, "explorer.exe");
    assert_eq!(roots[0].children[0].label, "cmd.exe");
}

#[test]
fn refuses_to_overwrite_an_existing_case() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    build_case(&path);

    match CaseWriter::create(&path, init()) {
        Err(FormatError::CaseExists(p)) => assert_eq!(p, path),
        Err(other) => panic!("expected CaseExists, got {other:?}"),
        Ok(_) => panic!("expected CaseExists, but the existing case was overwritten"),
    }
}

#[test]
fn rejects_a_file_that_is_not_a_case() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plain.sqlite");
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE t(x)")
        .unwrap();

    match CaseReader::open(&path) {
        Err(FormatError::NotACase { .. }) => {}
        Err(other) => panic!("expected NotACase, got {other:?}"),
        Ok(_) => panic!("expected NotACase, but a plain SQLite file was accepted"),
    }
}

#[test]
fn interrupted_collection_still_yields_a_readable_case() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("partial.tpv");

    {
        let mut w = CaseWriter::create(&path, init()).unwrap();
        w.upsert_entity(&Entity::new(EntityKind::File, "c:\\a.exe", "a.exe"))
            .unwrap();
        w.add_event(&Event::new(
            ts(500),
            Source::Live,
            EventKind::ProcessSnapshot,
            "before the interruption",
        ))
        .unwrap();
        // Dropped without finish(), as if the collector had been killed.
    }

    let r = CaseReader::open(&path).unwrap();
    assert!(
        !r.meta().unwrap().finalized,
        "an unfinalized case must announce itself as partial"
    );
}

#[test]
fn a_case_with_no_events_has_no_time_span() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.tpv");
    CaseWriter::create(&path, init())
        .unwrap()
        .finish(custody())
        .unwrap();

    let r = CaseReader::open(&path).unwrap();
    assert_eq!(r.time_span().unwrap(), None);
    assert_eq!(r.counts().unwrap().events, 0);
    assert!(r.process_tree().unwrap().is_empty());
}

#[test]
fn the_axis_covers_inferred_events_but_not_unusable_ones() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");

    let mut w = CaseWriter::create(&path, init()).unwrap();

    // An artifact-derived event: a real recorded time.
    w.add_event(&Event::new(
        ts(1_000),
        Source::Prefetch,
        EventKind::ExecutionEvidence,
        "ran earlier",
    ))
    .unwrap();

    // A live observation. It carries the collection instant, which is later than
    // anything the artifacts recorded. This is the ordinary case for a service,
    // an autorun or an open socket, and it must be on the axis.
    w.add_event(&Event::new(
        ts(9_000).inferred(),
        Source::Services,
        EventKind::ServiceState,
        "service running at collection time",
    ))
    .unwrap();

    // A never-set FILETIME. This one really is unplaceable and must not drag the
    // axis back to 1601.
    w.add_event(&Event::new(
        Timestamp::from_filetime(0),
        Source::Mft,
        EventKind::FileMetadata,
        "$SI creation time is zero",
    ))
    .unwrap();

    w.finish(custody()).unwrap();

    let r = CaseReader::open(&path).unwrap();
    let (lo, hi) = r.time_span().unwrap().expect("a span exists");
    assert_eq!(lo, 1_000);
    assert_eq!(
        hi, 9_000,
        "the collection instant is the newest thing in a live case; excluding it \
         would push the entire live snapshot past the right edge of its own axis"
    );

    // And the whole case is reachable through a filter bounded by that span,
    // which is exactly what the viewer sends.
    assert_eq!(
        r.count_events(&EventFilter::in_range(lo, hi)).unwrap(),
        2,
        "only the unplaceable event may fall outside the axis"
    );
}

#[test]
fn process_nodes_carry_the_fields_an_analyst_triages_on() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");

    let mut w = CaseWriter::create(&path, init()).unwrap();
    let key = ProcessKey::new(1337, 3_000);
    w.upsert_entity(&Entity::process(key, "evil.exe").with_attrs(serde_json::json!({
        "image_path": r"C:\Users\Public\evil.exe",
        "command_line": r"evil.exe --beacon https://c2.example",
        "user": "TARGET\\victim",
        "elevated": false,
    })))
    .unwrap();
    w.add_event(
        &Event::new(ts(3_000), Source::Live, EventKind::ProcessSnapshot, "alive")
            .with_entity(key.natural_key()),
    )
    .unwrap();

    // A process the collector could not open, which is common when running
    // without elevation and must be visible as such rather than as blanks.
    let opaque = ProcessKey::new(4, 0);
    w.upsert_entity(&Entity::process(opaque, "System").with_attrs(serde_json::json!({
        "access_error": "OpenProcess failed: access denied",
    })))
    .unwrap();
    w.finish(custody()).unwrap();

    let roots = CaseReader::open(&path).unwrap().process_tree().unwrap();
    let evil = roots.iter().find(|n| n.label == "evil.exe").unwrap();
    assert_eq!(evil.command_line.as_deref(), Some("evil.exe --beacon https://c2.example"));
    assert_eq!(evil.image.as_deref(), Some(r"C:\Users\Public\evil.exe"));
    assert_eq!(evil.user.as_deref(), Some("TARGET\\victim"));
    assert_eq!(evil.elevated, Some(false));

    let system = roots.iter().find(|n| n.label == "System").unwrap();
    assert_eq!(system.command_line, None);
    assert_eq!(
        system.access_error.as_deref(),
        Some("OpenProcess failed: access denied"),
        "an empty field must be distinguishable from a field we were denied"
    );
}

#[test]
fn a_process_with_no_known_creation_time_is_marked_rather_than_dated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");

    let mut w = CaseWriter::create(&path, init()).unwrap();
    // A PID-only key: the collector could not read the creation time.
    let opaque = ProcessKey::pid_only(4);
    w.upsert_entity(&Entity::process(opaque, "System")).unwrap();
    w.add_event(
        &Event::new(
            ts(7_000).inferred(),
            Source::Live,
            EventKind::ProcessSnapshot,
            "seen at collection",
        )
        .with_entity(opaque.natural_key()),
    )
    .unwrap();
    w.finish(custody()).unwrap();

    let roots = CaseReader::open(&path).unwrap().process_tree().unwrap();
    let started = roots[0].started.as_ref().expect("a position on the axis");
    assert_eq!(started.ns, 7_000, "falls back to when we first saw it");
    assert!(
        !started.exact,
        "presenting an observation time as a start time would let collection \
         order be read as execution order"
    );
}

#[test]
fn an_entity_reads_back_with_its_attributes_decompressed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    build_case(&path);

    let r = CaseReader::open(&path).unwrap();
    let leaf = ProcessKey::new(1337, 3_000);
    let e = r.entity(&leaf.natural_key()).unwrap().expect("entity exists");

    assert_eq!(e.kind, "process");
    assert_eq!(e.label, "evil.exe");
    assert_eq!(
        e.attrs.unwrap()["cmdline"],
        serde_json::json!("evil.exe --beacon")
    );
    assert_eq!(e.event_count, 2, "one snapshot and one connection");
    assert_eq!(e.first_seen_ns, Some(3_000));

    assert!(r.entity("process:9999:0").unwrap().is_none());
}

#[test]
fn related_entities_are_reachable_in_both_directions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    build_case(&path);

    let r = CaseReader::open(&path).unwrap();
    let mid = ProcessKey::new(800, 2_000);
    let related = r.related(&mid.natural_key(), 64).unwrap();

    // services.exe is both a child of System and the parent of evil.exe, so an
    // analyst inspecting it must see the edge pointing each way.
    let child = related
        .iter()
        .find(|x| x.outgoing && x.kind == "parent_of")
        .expect("outgoing parent_of");
    assert_eq!(child.entity.label, "evil.exe");

    let parent = related
        .iter()
        .find(|x| !x.outgoing && x.kind == "parent_of")
        .expect("incoming parent_of");
    assert_eq!(parent.entity.label, "System");
}

#[test]
fn a_single_event_can_be_refetched_by_id() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    build_case(&path);

    let r = CaseReader::open(&path).unwrap();
    let net = r
        .events(
            &EventFilter {
                network_only: true,
                ..Default::default()
            },
            1,
            0,
        )
        .unwrap()
        .remove(0);

    let again = r.event(net.id).unwrap().expect("event exists");
    assert_eq!(again, net);
    assert!(r.event(999_999).unwrap().is_none());
}

#[test]
fn filter_facets_describe_only_what_the_case_contains() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    build_case(&path);

    let r = CaseReader::open(&path).unwrap();
    let sources = r.source_counts().unwrap();

    let names: Vec<&str> = sources.iter().map(|(s, _)| s.as_str()).collect();
    assert!(names.contains(&"live"));
    assert!(names.contains(&"prefetch"));
    assert!(
        !names.contains(&"evtx"),
        "no EVTX was collected, so offering that filter would imply it was empty"
    );

    let total: i64 = sources.iter().map(|(_, n)| n).sum();
    assert_eq!(total, r.counts().unwrap().events);
    assert!(
        sources.windows(2).all(|w| w[0].1 >= w[1].1),
        "facets come back ordered by volume"
    );
}

#[test]
fn ioc_lines_match_any_one_of_them() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    build_case(&path);
    let r = CaseReader::open(&path).unwrap();

    let one = EventFilter {
        iocs: vec!["203.0.113.7".into(), "no-such-ioc".into()],
        ..Default::default()
    };
    assert_eq!(r.count_events(&one).unwrap(), 1);

    let either = EventFilter {
        iocs: vec!["203.0.113.7".into(), "EVIL.EXE".into()],
        ..Default::default()
    };
    assert!(
        r.count_events(&either).unwrap() >= 2,
        "IP and filename must OR, not AND"
    );
}

#[test]
fn local_rules_name_the_events_they_rest_on() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    let mut w = CaseWriter::create(&path, init()).unwrap();
    w.add_event(
        &Event::new(
            ts(1_000),
            Source::Evtx,
            EventKind::ServiceInstall,
            "[7045] service evil installed: C:\\Temp\\s.exe",
        )
        .with_log_id(7045),
    )
    .unwrap();
    w.add_event(
        &Event::new(
            ts(2_000),
            Source::Registry,
            EventKind::AutostartEntry,
            "Updater runs C:\\Temp\\r.exe",
        )
        .with_path(r"C:\Temp\r.exe"),
    )
    .unwrap();
    w.add_event(
        &Event::new(
            ts(3_000),
            Source::Evtx,
            EventKind::ProcessStart,
            "powershell (pid 9) started: powershell -EncodedCommand AQID",
        )
        .with_process(9, Some(1), Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into())),
    )
    .unwrap();
    w.add_event(
        &Event::new(
            ts(4_000),
            Source::Evtx,
            EventKind::LogonSession,
            "logon CORP\\alice type 10 from 203.0.113.8",
        )
        .with_user(r"CORP\alice"),
    )
    .unwrap();
    w.add_event(
        &Event::new(
            ts(5_000),
            Source::Memory,
            EventKind::ProcessSnapshot,
            "malware.exe — found in the pool but MISSING from the kernel's process list",
        )
        .with_process(66, Some(4), Some(r"C:\Temp\malware.exe".into())),
    )
    .unwrap();
    w.add_event(
        &Event::new(
            ts(6_000),
            Source::Live,
            EventKind::ProcessSnapshot,
            "orphan.exe (pid 99) running",
        )
        .with_process(99, Some(12_345), Some(r"C:\Temp\orphan.exe".into())),
    )
    .unwrap();
    w.finish(custody()).unwrap();

    let mut r = CaseReader::open_for_findings(&path).unwrap();
    let n = r.regenerate_findings().unwrap();
    assert!(n >= 6, "expected the six staple rules, got {n}");
    let rules: Vec<String> = r.findings().unwrap().into_iter().map(|f| f.rule).collect();
    for need in [
        "evtx.service_install",
        "live.autostart_entry",
        "exec.encoded_powershell",
        "evtx.logon_type_10",
        "mem.eprocess_unlinked",
        "live.process_orphan",
    ] {
        assert!(rules.iter().any(|r| r == need), "missing {need} in {rules:?}");
    }
}

#[test]
fn csv_export_quotes_commas_in_summaries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.tpv");
    build_case(&path);
    let r = CaseReader::open(&path).unwrap();
    let rows = r.events(&EventFilter::default(), 50, 0).unwrap();
    let csv = crate::events_csv(&rows);
    assert!(csv.starts_with("utc,source,kind,"));
    assert!(csv.contains("evil.exe") || csv.contains("EVIL.EXE"));
    let md = crate::case_markdown(
        &r.meta().unwrap(),
        &r.counts().unwrap(),
        &r.manifest().unwrap(),
        &[],
        &rows[..rows.len().min(3)],
        rows.len() as i64,
    );
    assert!(md.contains("GELADEIRA"));
    assert!(md.contains("Custody"));
}


