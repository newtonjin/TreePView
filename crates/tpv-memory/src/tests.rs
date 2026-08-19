use crate::dtb;
use crate::image::{ImageFormat, PhysicalMemory};
use crate::paging::AddressSpace;
use crate::process::Discovery;
use crate::profile;
use crate::synthetic::{layout, Builder, ProcessSpec};
use crate::Analysis;

/// 2023-06-01 in Windows FILETIME, and a few plausible moments after it.
const T0: u64 = 133_302_240_000_000_000;
const T1: u64 = T0 + 30 * 10_000_000;
const T2: u64 = T0 + 600 * 10_000_000;
const T3: u64 = T0 + 900 * 10_000_000;
const T4: u64 = T0 + 3600 * 10_000_000;

const EVIL_CMDLINE: &str =
    "C:\\Users\\victim\\AppData\\Local\\Temp\\svch0st.exe -enc SQBFAFgAIAAoAE4A";

fn host() -> PhysicalMemory {
    Builder::new(48 << 20).build(&[
        ProcessSpec::kernel("System", 4, 0, T0),
        ProcessSpec::kernel("smss.exe", 300, 4, T1),
        ProcessSpec::user("explorer.exe", 1000, 300, T2, "C:\\Windows\\explorer.exe")
            .with_modules(&[
                ("C:\\Windows\\System32\\ntdll.dll", 0x7fff_1000_0000, 0x1f_0000),
                ("C:\\Windows\\System32\\kernel32.dll", 0x7fff_2000_0000, 0xc_0000),
            ]),
        ProcessSpec::user("svchost.exe", 800, 300, T2, "C:\\Windows\\System32\\svchost.exe -k netsvcs"),
        ProcessSpec::user("notepad.exe", 4020, 1000, T3, "\"C:\\Windows\\notepad.exe\" secrets.txt"),
        // The one the whole exercise is for: present in the pool, absent from
        // the kernel's list, and still running.
        ProcessSpec::user("svch0st.exe", 6660, 1000, T4, EVIL_CMDLINE).unlinked(),
    ])
}

#[test]
fn a_flat_image_is_one_run_starting_at_zero() {
    let mem = PhysicalMemory::from_bytes(vec![0u8; 0x4000]).unwrap();
    assert_eq!(mem.format(), ImageFormat::Raw);
    assert_eq!(mem.runs().len(), 1);
    assert_eq!(mem.captured_bytes(), 0x4000);
}

#[test]
fn a_crash_dump_is_read_through_its_run_list_not_as_a_flat_file() {
    // Two runs with a hole between them. Read flat, the second run would appear
    // at the wrong physical address, and every pointer into it would be wrong.
    let mut b = vec![0u8; 0x2000 + 0x3000];
    b[..8].copy_from_slice(b"PAGEDU64");
    b[0x88..0x8c].copy_from_slice(&2u32.to_le_bytes());
    b[0x98..0xa0].copy_from_slice(&1u64.to_le_bytes()); // run 0 at page 1
    b[0xa0..0xa8].copy_from_slice(&1u64.to_le_bytes()); // one page
    b[0xa8..0xb0].copy_from_slice(&0x10u64.to_le_bytes()); // run 1 at page 0x10
    b[0xb0..0xb8].copy_from_slice(&2u64.to_le_bytes()); // two pages
    b[0x2000] = 0xaa;
    b[0x3000] = 0xbb;

    let mem = PhysicalMemory::from_bytes(b).unwrap();
    assert_eq!(mem.format(), ImageFormat::CrashDump64);
    assert_eq!(mem.read_u32(0x1000).unwrap() & 0xff, 0xaa);
    assert_eq!(mem.read_u32(0x10000).unwrap() & 0xff, 0xbb);
    assert!(!mem.is_mapped(0x5000), "the hole between runs is not memory");
}

#[test]
fn translation_handles_four_kilobyte_and_large_pages() {
    let mut b = Builder::new(8 << 20);
    let dtb = b.kernel_dtb();
    let small = b.alloc_page();
    b.write_u64(small, 0xdead_beef_0000_0001);
    b.map(dtb, 0xFFFF_8002_0000_0000, small);
    let mem = b.build(&[]);

    let space = AddressSpace::new(&mem, dtb);
    assert_eq!(space.read_u64(0xFFFF_8002_0000_0000).unwrap(), 0xdead_beef_0000_0001);
    assert!(space.translate(0xFFFF_8002_0001_0000).is_none(), "unmapped stays unmapped");
}

#[test]
fn the_page_table_root_is_found_by_its_self_reference() {
    let mem = host();
    let found = dtb::candidates(&mem);
    assert!(!found.is_empty(), "a Windows-shaped address space has a self-map");
    // The kernel's own root is the one with no user half, and it must rank first
    // or every later stage starts from the wrong address space.
    assert_eq!(found[0].user_entries, 0);
    assert!(found[0].kernel_entries > 0);
}

#[test]
fn the_eprocess_layout_is_recovered_without_symbols() {
    let mem = host();
    let roots = dtb::candidates(&mem);
    let p = profile::calibrate(&mem, &roots).expect("a calibrated profile");

    // Every offset is expressed relative to ActiveProcessLinks, so the expected
    // values are the differences between the offsets the image was built with.
    let apl = layout::ACTIVE_PROCESS_LINKS as i64;
    assert_eq!(p.layout.unique_process_id, layout::UNIQUE_PROCESS_ID as i64 - apl);
    assert_eq!(p.layout.directory_table_base, layout::DTB as i64 - apl);
    assert_eq!(p.layout.create_time, layout::CREATE_TIME as i64 - apl);
    assert_eq!(p.layout.exit_time, layout::EXIT_TIME as i64 - apl);
    assert_eq!(p.layout.inherited_from_pid, layout::INHERITED_FROM_PID as i64 - apl);
    assert_eq!(p.layout.image_file_name, layout::IMAGE_FILE_NAME as i64 - apl);
    assert_eq!(p.layout.peb, Some(layout::PEB as i64 - apl));
}

#[test]
fn calibration_reports_how_well_the_layout_agreed_with_the_image() {
    let mem = host();
    let roots = dtb::candidates(&mem);
    let p = profile::calibrate(&mem, &roots).unwrap();
    // One entry in the ring is PsActiveProcessHead, which has no process fields,
    // so perfect agreement is not achievable and not expected.
    assert!(p.agreement >= 70, "agreement was {}", p.agreement);
    assert!(p.linked_entries >= 6);
}

#[test]
fn every_linked_process_is_recovered_with_its_identity() {
    let a = Analysis::from_memory(host()).unwrap();
    let names: Vec<&str> = a.processes().iter().map(|p| p.name.as_str()).collect();
    for want in ["System", "smss.exe", "explorer.exe", "svchost.exe", "notepad.exe"] {
        assert!(names.contains(&want), "missing {want}; found {names:?}");
    }

    let notepad = a.processes().iter().find(|p| p.name == "notepad.exe").unwrap();
    assert_eq!(notepad.pid, 4020);
    assert_eq!(notepad.ppid, 1000);
    assert_eq!(notepad.create_time, T3);
    assert_eq!(notepad.exit_time, 0);
}

#[test]
fn a_process_unlinked_from_the_kernel_list_is_still_found_and_flagged() {
    let a = Analysis::from_memory(host()).unwrap();

    let evil = a
        .processes()
        .iter()
        .find(|p| p.name == "svch0st.exe")
        .expect("the pool allocation survives being unlinked");
    assert_eq!(evil.discovery, Discovery::Unlinked);
    assert!(evil.hidden_from_list(), "still running and not in the list");

    let hidden: Vec<u64> = a.hidden().map(|p| p.pid).collect();
    assert_eq!(hidden, vec![6660], "exactly one process is hiding");
}

#[test]
fn an_ordinary_process_is_not_mistaken_for_a_hidden_one() {
    let a = Analysis::from_memory(host()).unwrap();
    for p in a.processes().iter().filter(|p| p.name != "svch0st.exe") {
        assert!(
            !p.hidden_from_list(),
            "{} was wrongly reported as hidden ({:?})",
            p.name,
            p.discovery
        );
    }
}

#[test]
fn command_lines_are_recovered_from_the_process_address_space() {
    let a = Analysis::from_memory(host()).unwrap();

    let notepad = a.processes().iter().find(|p| p.name == "notepad.exe").unwrap();
    assert_eq!(
        notepad.command_line.as_deref(),
        Some("\"C:\\Windows\\notepad.exe\" secrets.txt")
    );
    assert_eq!(notepad.current_directory.as_deref(), Some("C:\\Windows\\system32\\"));
}

#[test]
fn a_hidden_process_still_gives_up_its_command_line() {
    // The whole reason to carry the PEB read through to unlinked processes: the
    // argument list is normally the most incriminating thing about them, and
    // being absent from the kernel's list does not protect it.
    let a = Analysis::from_memory(host()).unwrap();
    let evil = a.processes().iter().find(|p| p.name == "svch0st.exe").unwrap();
    assert_eq!(evil.command_line.as_deref(), Some(EVIL_CMDLINE));
}

#[test]
fn loaded_modules_are_read_from_the_loader_list() {
    let a = Analysis::from_memory(host()).unwrap();
    let explorer = a.processes().iter().find(|p| p.name == "explorer.exe").unwrap();

    let names: Vec<&str> = explorer.modules.iter().map(|m| m.full_name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "C:\\Windows\\System32\\ntdll.dll",
            "C:\\Windows\\System32\\kernel32.dll"
        ]
    );
    assert_eq!(explorer.modules[0].base, 0x7fff_1000_0000);
    assert_eq!(explorer.modules[0].size, 0x1f_0000);
}

#[test]
fn processes_are_returned_oldest_first() {
    let a = Analysis::from_memory(host()).unwrap();
    let times: Vec<u64> = a.processes().iter().map(|p| p.create_time).collect();
    let mut sorted = times.clone();
    sorted.sort_unstable();
    assert_eq!(times, sorted);
}

#[test]
fn an_image_with_no_windows_kernel_in_it_fails_clearly() {
    // Random-looking data with no process list. The failure has to name what was
    // missing, because "it didn't work" on a 16 GB acquisition is not actionable.
    let mem = PhysicalMemory::raw_from_bytes(vec![0x41u8; 4 << 20]);
    let text = match Analysis::from_memory(mem) {
        Ok(_) => panic!("a page of repeated 'A' is not a Windows memory image"),
        Err(e) => e.to_string(),
    };
    assert!(
        text.contains("page-table root") || text.contains("System process"),
        "unhelpful error: {text}"
    );
}

#[test]
fn a_process_that_exited_is_not_reported_as_hidden() {
    let mem = Builder::new(48 << 20).build(&[
        ProcessSpec::kernel("System", 4, 0, T0),
        ProcessSpec::kernel("smss.exe", 300, 4, T1),
        ProcessSpec::user("explorer.exe", 1000, 300, T2, "C:\\Windows\\explorer.exe"),
        ProcessSpec::user("svchost.exe", 800, 300, T2, "C:\\Windows\\System32\\svchost.exe"),
        ProcessSpec::user("cmd.exe", 5000, 1000, T3, "cmd.exe /c whoami")
            .exited(T4)
            .unlinked(),
    ]);
    let a = Analysis::from_memory(mem).unwrap();

    let cmd = a.processes().iter().find(|p| p.name == "cmd.exe").unwrap();
    assert_eq!(cmd.discovery, Discovery::Unlinked);
    assert_eq!(cmd.exit_time, T4);
    assert!(
        !cmd.hidden_from_list(),
        "a process with an exit time left the list legitimately"
    );
    assert_eq!(a.hidden().count(), 0);
}
