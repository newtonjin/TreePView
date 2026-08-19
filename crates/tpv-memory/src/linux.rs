//! Linux process recovery from memory images.
//!
//! Two routes, in decreasing confidence:
//!
//! 1. **ELF core notes.** A process-core (`gcore`, some crash handlers) and some
//!    QEMU dumps carry `NT_PRPSINFO` / `NT_FILE`. Those are the kernel's own
//!    words about the process and need no symbols.
//! 2. **A `task_struct` scan.** LiME and raw Linux RAM have no notes. The comm
//!    field is a 16-byte NUL-padded name; once `kthreadd` (pid 2) teaches us
//!    where `pid` sits relative to `comm`, the rest of the list is a linear
//!    scan. That offset varies by kernel config, so the result is a heuristic
//!    and is labelled as such.
//!
//! Windows analysis is not attempted on LiME images: a Linux capture has no
//! `EPROCESS` list, and running the Windows calibrator over it is slow and
//! would fail with an unhelpful page-table error.

use std::collections::BTreeMap;

use crate::image::PhysicalMemory;
use crate::process::{Discovery, MemModule, MemProcess};

const NT_PRPSINFO: u32 = 3;
const NT_FILE: u32 = 0x4649_4C45; // "FILE"
const PT_NOTE: u32 = 4;
const PT_LOAD: u32 = 1;

/// Kernel banner, if the image still has `Linux version ` in captured RAM.
pub fn kernel_banner(mem: &PhysicalMemory) -> Option<String> {
    const NEEDLE: &[u8] = b"Linux version ";
    for run in mem.runs() {
        let Some(slice) = mem.slice_at(run.phys) else { continue };
        let Some(pos) = memchr::memmem::find(slice, NEEDLE) else { continue };
        let rest = &slice[pos..];
        let end = rest
            .iter()
            .position(|&c| c == b'\n' || c == 0)
            .unwrap_or(rest.len())
            .min(240);
        let s = String::from_utf8_lossy(&rest[..end]).trim().to_string();
        if s.len() > NEEDLE.len() {
            return Some(s);
        }
    }
    None
}

/// Processes described by ELF notes in the file (not in physical RAM).
pub fn from_elf_notes(file: &[u8]) -> Vec<MemProcess> {
    let mut processes = Vec::new();
    let mut files: Vec<MemModule> = Vec::new();

    for desc in note_descriptors(file) {
        match desc.n_type {
            NT_PRPSINFO => {
                if let Some(p) = parse_prpsinfo(desc.payload) {
                    processes.push(p);
                }
            }
            NT_FILE => {
                files.extend(parse_nt_file(desc.payload));
            }
            _ => {}
        }
    }

    // A process-core typically has one PRPSINFO and a mapped-file list that
    // belongs to that process. Attach the files rather than inventing modules
    // with no owner.
    if processes.len() == 1 && !files.is_empty() {
        processes[0].modules = files;
        if processes[0].image_path.is_none() {
            processes[0].image_path = processes[0]
                .modules
                .iter()
                .map(|m| m.full_name.clone())
                .find(|n| !n.starts_with('['));
        }
    }

    processes
}

/// Scan physical memory for Linux tasks. Empty when the image does not look
/// like a Linux kernel (no `kthreadd` / `swapper/0` to learn a pid offset from).
pub fn scan_tasks(mem: &PhysicalMemory) -> Vec<MemProcess> {
    let Some(delta) = learn_pid_delta(mem) else {
        return Vec::new();
    };

    let mut by_pid: BTreeMap<u64, MemProcess> = BTreeMap::new();
    for run in mem.runs() {
        let Some(slice) = mem.slice_at(run.phys) else { continue };
        let mut off = 0usize;
        while off + 16 <= slice.len() {
            let comm_bytes: [u8; 16] = slice[off..off + 16].try_into().unwrap();
            if looks_like_comm(&comm_bytes) {
                let comm_pa = run.phys + off as u64;
                let pid_pa = comm_pa.wrapping_add(delta as u64);
                if let Some(pid) = read_u32_pa(mem, pid_pa) {
                    if pid <= 4_000_000 {
                        let name = comm_string(&comm_bytes);
                        by_pid.entry(pid as u64).or_insert_with(|| MemProcess {
                            pid: pid as u64,
                            ppid: 0,
                            name,
                            dtb: 0,
                            create_time: 0,
                            exit_time: 0,
                            discovery: Discovery::Heuristic,
                            eprocess_pa: Some(comm_pa),
                            apl_va: None,
                            peb_va: None,
                            command_line: None,
                            image_path: None,
                            current_directory: None,
                            modules: Vec::new(),
                        });
                    }
                }
            }
            off += 8;
        }
        if by_pid.len() >= 4096 {
            break;
        }
    }

    by_pid.into_values().collect()
}

struct NoteDesc<'a> {
    n_type: u32,
    payload: &'a [u8],
}

fn note_descriptors(file: &[u8]) -> Vec<NoteDesc<'_>> {
    if file.len() < 64 || &file[0..4] != b"\x7fELF" || file[4] != 2 || file[5] != 1 {
        return Vec::new();
    }
    let phoff = le64(file, 0x20) as usize;
    let phentsize = le16(file, 0x36) as usize;
    let phnum = le16(file, 0x38) as usize;
    if phentsize < 56 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0..phnum {
        let at = phoff.saturating_add(i.saturating_mul(phentsize));
        if at + 56 > file.len() {
            break;
        }
        if le32(file, at) != PT_NOTE {
            continue;
        }
        let offset = le64(file, at + 0x08) as usize;
        let filesz = le64(file, at + 0x20) as usize;
        if offset.saturating_add(filesz) > file.len() {
            continue;
        }
        parse_notes(&file[offset..offset + filesz], &mut out);
    }
    let _ = PT_LOAD;
    out
}

fn parse_notes<'a>(notes: &'a [u8], out: &mut Vec<NoteDesc<'a>>) {
    let mut at = 0usize;
    while at + 12 <= notes.len() {
        let namesz = le32(notes, at) as usize;
        let descsz = le32(notes, at + 4) as usize;
        let n_type = le32(notes, at + 8);
        let name_pad = (namesz + 3) & !3;
        let desc_pad = (descsz + 3) & !3;
        let desc_at = at + 12 + name_pad;
        let next = desc_at.saturating_add(desc_pad);
        if desc_at + descsz > notes.len() {
            break;
        }
        out.push(NoteDesc { n_type, payload: &notes[desc_at..desc_at + descsz] });
        if next <= at {
            break;
        }
        at = next;
    }
}

/// x86_64 `elf_prpsinfo`: pid at 24, ppid at 28, fname at 40, psargs at 56.
fn parse_prpsinfo(desc: &[u8]) -> Option<MemProcess> {
    if desc.len() < 136 {
        return None;
    }
    let pid = le32(desc, 24) as u64;
    let ppid = le32(desc, 28) as u64;
    let name = cstring(&desc[40..56]);
    if name.is_empty() {
        return None;
    }
    let args = cstring(&desc[56..desc.len().min(136)]);
    Some(MemProcess {
        pid,
        ppid,
        name,
        dtb: 0,
        create_time: 0,
        exit_time: 0,
        discovery: Discovery::ElfNotes,
        eprocess_pa: None,
        apl_va: None,
        peb_va: None,
        command_line: (!args.is_empty()).then_some(args),
        image_path: None,
        current_directory: None,
        modules: Vec::new(),
    })
}

fn parse_nt_file(desc: &[u8]) -> Vec<MemModule> {
    if desc.len() < 16 {
        return Vec::new();
    }
    let count = le64(desc, 0) as usize;
    if count == 0 || count > 64_000 {
        return Vec::new();
    }
    let table = 16;
    let table_len = count.saturating_mul(24);
    if table + table_len > desc.len() {
        return Vec::new();
    }
    let mut names = desc[table + table_len..].split(|b| *b == 0);
    let mut out = Vec::new();
    for i in 0..count {
        let start = le64(desc, table + i * 24);
        let end = le64(desc, table + i * 24 + 8);
        let name = names
            .next()
            .map(|n| String::from_utf8_lossy(n).into_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("mapping@{start:#x}"));
        let size = end.saturating_sub(start) as u32;
        out.push(MemModule { base: start, size, full_name: name });
    }
    out
}

fn learn_pid_delta(mem: &PhysicalMemory) -> Option<i32> {
    // kthreadd is pid 2 on every Linux kernel; swapper/0 is pid 0 and matches
    // too many zeroes in RAM to be a teacher.
    for run in mem.runs() {
        let Some(slice) = mem.slice_at(run.phys) else { continue };
        let mut from = 0usize;
        while let Some(pos) = memchr::memmem::find(&slice[from..], b"kthreadd\0") {
            let at = from + pos;
            if at + 16 > slice.len() {
                break;
            }
            let mut comm = [0u8; 16];
            comm.copy_from_slice(&slice[at..at + 16]);
            if looks_like_comm(&comm) {
                let comm_pa = run.phys + at as u64;
                if let Some(delta) = pid_delta_for(mem, comm_pa, 2) {
                    return Some(delta);
                }
            }
            from = at + 1;
        }
    }
    None
}

fn pid_delta_for(mem: &PhysicalMemory, comm_pa: u64, expected: u32) -> Option<i32> {
    let mut delta = -4i32;
    while delta >= -0x800 {
        let pa = comm_pa.wrapping_add(delta as u64);
        if let Some(pid) = read_u32_pa(mem, pa) {
            if pid == expected {
                // tgid sits next to pid on every modern kernel.
                let tgid = read_u32_pa(mem, pa.wrapping_add(4))
                    .or_else(|| read_u32_pa(mem, pa.wrapping_add(8)));
                if tgid == Some(expected) || tgid == Some(0) && expected == 0 {
                    return Some(delta);
                }
            }
        }
        delta -= 4;
    }
    None
}

fn read_u32_pa(mem: &PhysicalMemory, pa: u64) -> Option<u32> {
    let s = mem.slice_at(pa)?;
    if s.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn looks_like_comm(b: &[u8; 16]) -> bool {
    if b[0] == 0 {
        return false;
    }
    let mut seen_nul = false;
    for &c in b {
        if seen_nul {
            if c != 0 {
                return false;
            }
        } else if c == 0 {
            seen_nul = true;
        } else if !is_comm_char(c) {
            return false;
        }
    }
    seen_nul
}

fn is_comm_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'/' | b'.' | b':' | b'+' | b'@')
}

fn comm_string(b: &[u8; 16]) -> String {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..n]).into_owned()
}

fn cstring(b: &[u8]) -> String {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..n]).trim().to_string()
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn le64(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf_core_with_prpsinfo(name: &str, pid: u32, ppid: u32, args: &str) -> Vec<u8> {
        let mut prps = vec![0u8; 136];
        prps[24..28].copy_from_slice(&pid.to_le_bytes());
        prps[28..32].copy_from_slice(&ppid.to_le_bytes());
        let nb = name.as_bytes();
        prps[40..40 + nb.len().min(15)].copy_from_slice(&nb[..nb.len().min(15)]);
        let ab = args.as_bytes();
        prps[56..56 + ab.len().min(79)].copy_from_slice(&ab[..ab.len().min(79)]);

        let name_bytes = b"CORE\0";
        let namesz = name_bytes.len();
        let name_pad = (namesz + 3) & !3;
        let desc_pad = (prps.len() + 3) & !3;
        let mut note = Vec::new();
        note.extend_from_slice(&(namesz as u32).to_le_bytes());
        note.extend_from_slice(&(prps.len() as u32).to_le_bytes());
        note.extend_from_slice(&NT_PRPSINFO.to_le_bytes());
        note.extend_from_slice(name_bytes);
        note.resize(12 + name_pad, 0);
        note.extend_from_slice(&prps);
        note.resize(12 + name_pad + desc_pad, 0);

        let load_off = 0x1000u64;
        let note_off = 0x200u64;
        let mut file = vec![0u8; 0x2000];
        file[0..4].copy_from_slice(b"\x7fELF");
        file[4] = 2;
        file[5] = 1;
        file[6] = 1;
        file[16..18].copy_from_slice(&4u16.to_le_bytes()); // ET_CORE
        file[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        file[20..24].copy_from_slice(&1u32.to_le_bytes());
        file[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        file[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        file[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        file[56..58].copy_from_slice(&2u16.to_le_bytes()); // e_phnum

        // PHDR 0: PT_LOAD
        let ph0 = 64;
        file[ph0..ph0 + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        file[ph0 + 8..ph0 + 16].copy_from_slice(&load_off.to_le_bytes());
        file[ph0 + 32..ph0 + 40].copy_from_slice(&0x1000u64.to_le_bytes());

        // PHDR 1: PT_NOTE
        let ph1 = 64 + 56;
        file[ph1..ph1 + 4].copy_from_slice(&PT_NOTE.to_le_bytes());
        file[ph1 + 8..ph1 + 16].copy_from_slice(&note_off.to_le_bytes());
        file[ph1 + 32..ph1 + 40].copy_from_slice(&(note.len() as u64).to_le_bytes());

        file[note_off as usize..note_off as usize + note.len()].copy_from_slice(&note);
        file
    }

    #[test]
    fn prpsinfo_notes_yield_the_process() {
        let bytes = elf_core_with_prpsinfo("bash", 1420, 1410, "/bin/bash -l");
        let procs = from_elf_notes(&bytes);
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].name, "bash");
        assert_eq!(procs[0].pid, 1420);
        assert_eq!(procs[0].ppid, 1410);
        assert_eq!(procs[0].command_line.as_deref(), Some("/bin/bash -l"));
        assert_eq!(procs[0].discovery, Discovery::ElfNotes);
    }

    #[test]
    fn a_banner_in_physical_memory_is_recovered() {
        let mut payload = vec![0u8; 0x2000];
        let banner = b"Linux version 6.1.0-generic (gcc) SMP\n";
        payload[0x40..0x40 + banner.len()].copy_from_slice(banner);
        let mem = PhysicalMemory::raw_from_bytes(payload);
        assert_eq!(
            kernel_banner(&mem).as_deref(),
            Some("Linux version 6.1.0-generic (gcc) SMP")
        );
    }

    #[test]
    fn kthreadd_teaches_the_pid_offset_used_by_the_scan() {
        // comm at 0x200, pid 2 and tgid 2 at comm-0x20. A second task at 0x400.
        let mut ram = vec![0u8; 0x1000];
        ram[0x200..0x209].copy_from_slice(b"kthreadd\0");
        ram[0x1E0..0x1E4].copy_from_slice(&2u32.to_le_bytes());
        ram[0x1E4..0x1E8].copy_from_slice(&2u32.to_le_bytes());
        ram[0x400..0x405].copy_from_slice(b"sshd\0");
        ram[0x3E0..0x3E4].copy_from_slice(&142u32.to_le_bytes());
        ram[0x3E4..0x3E8].copy_from_slice(&142u32.to_le_bytes());
        let mem = PhysicalMemory::raw_from_bytes(ram);
        let procs = scan_tasks(&mem);
        let names: Vec<&str> = procs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"kthreadd"), "{names:?}");
        assert!(names.contains(&"sshd"), "{names:?}");
        let sshd = procs.iter().find(|p| p.name == "sshd").unwrap();
        assert_eq!(sshd.pid, 142);
        assert_eq!(sshd.discovery, Discovery::Heuristic);
    }

    #[test]
    fn analysis_treats_an_elf_core_as_linux_not_windows() {
        let bytes = elf_core_with_prpsinfo("sshd", 500, 1, "/usr/sbin/sshd -D");
        let mem = PhysicalMemory::from_bytes(bytes).unwrap();
        assert_eq!(mem.format(), crate::ImageFormat::ElfCore);
        let a = crate::Analysis::from_memory(mem).unwrap();
        assert_eq!(a.os(), crate::GuestOs::Linux);
        assert!(a.profile().is_none());
        assert_eq!(a.processes().len(), 1);
        assert_eq!(a.processes()[0].name, "sshd");
        assert_eq!(a.processes()[0].pid, 500);
    }

    #[test]
    fn a_lime_image_is_linux_even_without_a_process_list() {
        let mut payload = vec![0u8; 0x1000];
        let banner = b"Linux version 5.15.0-custom\n";
        payload[0x10..0x10 + banner.len()].copy_from_slice(banner);
        let mut file = Vec::new();
        file.extend_from_slice(&0x4C69_4D45u32.to_le_bytes());
        file.extend_from_slice(&1u32.to_le_bytes());
        file.extend_from_slice(&0u64.to_le_bytes());
        file.extend_from_slice(&0xfffu64.to_le_bytes());
        file.extend_from_slice(&0u64.to_le_bytes());
        file.extend_from_slice(&payload);
        let mem = PhysicalMemory::from_bytes(file).unwrap();
        assert_eq!(mem.format(), crate::ImageFormat::Lime);
        let a = crate::Analysis::from_memory(mem).unwrap();
        assert_eq!(a.os(), crate::GuestOs::Linux);
        assert!(
            a.linux_banner().unwrap().starts_with("Linux version 5.15.0-custom"),
            "{:?}",
            a.linux_banner()
        );
    }
}
