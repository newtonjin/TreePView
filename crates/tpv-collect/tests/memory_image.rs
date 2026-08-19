//! A memory image, end to end, into a case a viewer can open.
//!
//! The image is synthesised rather than captured, so every fact the analysis
//! reports can be checked against something deliberately placed in it — most of
//! all the process that was put in the pool and left out of the kernel's list,
//! which is the finding this whole path exists to surface.

use std::io::Write;

use tpv_collect::memory::{run, MemoryConfig};
use tpv_format::{CaseReader, EventFilter};
use tpv_memory::synthetic::{Builder, ProcessSpec};
use tpv_model::MemoryMode;

const T0: u64 = 133_302_240_000_000_000;
const T1: u64 = T0 + 30 * 10_000_000;
const T2: u64 = T0 + 600 * 10_000_000;
const T3: u64 = T0 + 3600 * 10_000_000;

const IMPLANT_CMDLINE: &str = "C:\\ProgramData\\svch0st.exe -c 203.0.113.7:443";

fn image_bytes() -> Vec<u8> {
    Builder::new(48 << 20).build_bytes(&[
        ProcessSpec::kernel("System", 4, 0, T0),
        ProcessSpec::kernel("smss.exe", 300, 4, T1),
        ProcessSpec::user("explorer.exe", 1000, 300, T2, "C:\\Windows\\explorer.exe")
            .with_modules(&[("C:\\Windows\\System32\\ntdll.dll", 0x7fff_1000_0000, 0x1f_0000)]),
        ProcessSpec::user(
            "svchost.exe",
            800,
            300,
            T2,
            "C:\\Windows\\System32\\svchost.exe -k netsvcs",
        ),
        ProcessSpec::user("svch0st.exe", 6660, 1000, T3, IMPLANT_CMDLINE).unlinked(),
    ])
}

struct Fixture {
    _dir: tempfile::TempDir,
    case: std::path::PathBuf,
}

fn analyse() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("memdump.raw");
    let mut f = std::fs::File::create(&image).unwrap();
    f.write_all(&image_bytes()).unwrap();
    f.sync_all().unwrap();
    drop(f);

    let case = dir.path().join("memory.tpv");
    run(&MemoryConfig {
        image,
        out: case.clone(),
        tool_version: "tpv/test".into(),
        command_line: "tpv memory memdump.raw -o memory.tpv".into(),
    })
    .expect("the image analyses");

    Fixture { _dir: dir, case }
}

#[test]
fn the_case_is_sealed_and_verifies() {
    let fx = analyse();
    let r = CaseReader::open(&fx.case).unwrap();
    assert!(r.verify_content_digest().unwrap());
    assert!(r.meta().unwrap().finalized);
}

#[test]
fn the_case_records_which_image_it_came_from() {
    let fx = analyse();
    let r = CaseReader::open(&fx.case).unwrap();

    let manifest = r.manifest().unwrap();
    let entry = manifest
        .iter()
        .find(|m| m.source_path.ends_with("memdump.raw"))
        .expect("the image is listed as the source artifact");
    assert!(
        entry.sha256.is_some(),
        "an analysis that cannot be tied to a specific image is not reproducible"
    );
    assert!(entry.size_bytes > 0);
}

#[test]
fn the_case_does_not_claim_to_have_been_collected_live() {
    let fx = analyse();
    let meta = CaseReader::open(&fx.case).unwrap().meta().unwrap();
    // Reading someone else's image on an examiner's workstation must not leave a
    // case that looks like it was taken from the subject machine.
    assert_eq!(meta.profile.memory, MemoryMode::ImageAnalysis);
    assert!(!meta.profile.live_state);
}

#[test]
fn every_process_in_the_image_reaches_the_timeline() {
    let fx = analyse();
    let roots = CaseReader::open(&fx.case).unwrap().process_tree().unwrap();

    fn names(nodes: &[tpv_format::ProcessNode], out: &mut Vec<String>) {
        for n in nodes {
            out.push(n.label.clone());
            names(&n.children, out);
        }
    }
    let mut found = Vec::new();
    names(&roots, &mut found);

    for want in ["System", "smss.exe", "explorer.exe", "svchost.exe", "svch0st.exe"] {
        assert!(found.contains(&want.to_string()), "missing {want} in {found:?}");
    }
}

#[test]
fn the_tree_is_rebuilt_from_the_parent_ids_in_the_image() {
    let fx = analyse();
    let roots = CaseReader::open(&fx.case).unwrap().process_tree().unwrap();

    let system = roots.iter().find(|n| n.label == "System").unwrap();
    let smss = system
        .children
        .iter()
        .find(|n| n.label == "smss.exe")
        .expect("smss is a child of System");
    let explorer = smss
        .children
        .iter()
        .find(|n| n.label == "explorer.exe")
        .expect("explorer's parent id points at smss in this image");
    assert!(
        explorer.children.iter().any(|n| n.label == "svch0st.exe"),
        "an unlinked process still has a parent id, and the lineage is what \
         makes it interpretable"
    );
}

#[test]
fn command_lines_survive_the_trip_into_the_case() {
    let fx = analyse();
    let r = CaseReader::open(&fx.case).unwrap();

    let hits = r
        .events(
            &EventFilter { text: Some("203.0.113.7".into()), ..Default::default() },
            16,
            0,
        )
        .unwrap();
    assert!(
        !hits.is_empty(),
        "the implant's command line must be searchable, not just stored"
    );
    assert!(hits[0].summary.contains(IMPLANT_CMDLINE));
}

#[test]
fn a_process_hidden_from_the_kernel_list_is_called_out() {
    let fx = analyse();
    let r = CaseReader::open(&fx.case).unwrap();

    let roots = r.process_tree().unwrap();
    fn find<'a>(
        nodes: &'a [tpv_format::ProcessNode],
        label: &str,
    ) -> Option<&'a tpv_format::ProcessNode> {
        for n in nodes {
            if n.label == label {
                return Some(n);
            }
            if let Some(hit) = find(&n.children, label) {
                return Some(hit);
            }
        }
        None
    }
    let implant = find(&roots, "svch0st.exe").unwrap();

    let entity = r.entity(&implant.key).unwrap().expect("the entity exists");
    let attrs = entity.attrs.expect("attributes are stored");
    assert_eq!(
        attrs.get("hidden_from_process_list").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        attrs.get("discovery").and_then(|v| v.as_str()),
        Some("pool scan only")
    );

    // And it must be visible without knowing to inspect attributes, because an
    // analyst scanning the timeline is the person who needs to notice it.
    let hits = r
        .events(
            &EventFilter { text: Some("MISSING".into()), ..Default::default() },
            16,
            0,
        )
        .unwrap();
    assert!(hits.iter().any(|e| e.summary.contains("svch0st.exe")));
}

#[test]
fn the_custody_record_warns_about_the_hidden_process() {
    let fx = analyse();
    let custody = CaseReader::open(&fx.case)
        .unwrap()
        .meta()
        .unwrap()
        .custody
        .expect("custody is written on finish");
    assert!(
        custody
            .warnings
            .iter()
            .any(|w| w.contains("not in the kernel's process list")),
        "a finding this severe belongs in the custody record too: {:?}",
        custody.warnings
    );
}

#[test]
fn loaded_modules_become_related_entities() {
    let fx = analyse();
    let r = CaseReader::open(&fx.case).unwrap();
    let roots = r.process_tree().unwrap();

    fn find<'a>(
        nodes: &'a [tpv_format::ProcessNode],
        label: &str,
    ) -> Option<&'a tpv_format::ProcessNode> {
        for n in nodes {
            if n.label == label {
                return Some(n);
            }
            if let Some(hit) = find(&n.children, label) {
                return Some(hit);
            }
        }
        None
    }
    let explorer = find(&roots, "explorer.exe").unwrap();

    let related = r.related(&explorer.key, 64).unwrap();
    assert!(
        related
            .iter()
            .any(|e| e.entity.label.eq_ignore_ascii_case("ntdll.dll")),
        "modules read out of the loader list must be reachable from the process"
    );
}
