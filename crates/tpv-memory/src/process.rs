//! Processes recovered from an image, by two independent routes.
//!
//! Walking `ActiveProcessLinks` gives what the kernel says is running. Scanning
//! the pool for `Proc` allocations gives what is actually still in memory. The
//! two disagree in exactly the cases worth investigating: a process unlinked
//! from the list to hide it appears only in the scan, and a process that exited
//! recently appears in the scan with an exit time set.
//!
//! Reporting how each process was found, rather than merging them into one list,
//! is the point. "Present in the pool but absent from the kernel's own list" is
//! a finding; a merged list would erase it.

use std::collections::BTreeMap;

use crate::error::Result;
use crate::image::PhysicalMemory;
use crate::paging::{is_kernel_va, is_user_va, AddressSpace};
use crate::profile::KernelProfile;
use crate::scan;

/// How a process came to our attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Discovery {
    /// In the kernel's list, as an ordinary running process should be.
    Linked,
    /// In the pool but not in the list. Either it exited and the allocation has
    /// not been reused, or something removed it from the list on purpose.
    Unlinked,
    /// Seen both ways, which is the normal state for a live process on a machine
    /// whose pool has not been recycled.
    Both,
    /// Recovered from ELF core notes (`NT_PRPSINFO` / `NT_FILE`).
    ElfNotes,
    /// Recovered by scanning for Linux `task_struct`-shaped comm/pid pairs.
    /// Lower confidence than a kernel walk; the case must say so.
    Heuristic,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MemProcess {
    pub pid: u64,
    pub ppid: u64,
    pub name: String,
    /// The process's own page-table root, and therefore the key to its memory.
    pub dtb: u64,
    /// Windows FILETIME, or zero when the field was never set.
    pub create_time: u64,
    pub exit_time: u64,
    pub discovery: Discovery,
    /// Where the structure was found, for anyone who wants to go and look.
    pub eprocess_pa: Option<u64>,
    pub apl_va: Option<u64>,
    pub peb_va: Option<u64>,
    pub command_line: Option<String>,
    pub image_path: Option<String>,
    pub current_directory: Option<String>,
    /// Empty when the module list could not be read, which is the usual outcome
    /// for a process whose user-mode pages were paged out.
    pub modules: Vec<MemModule>,
}

impl MemProcess {
    /// True when the kernel's own list does not mention this process.
    ///
    /// On its own this is suspicious rather than damning: a process that exited
    /// moments before acquisition looks identical. `exit_time` is what
    /// separates the two, and both are reported so the distinction stays with
    /// the analyst.
    pub fn hidden_from_list(&self) -> bool {
        self.discovery == Discovery::Unlinked && self.exit_time == 0
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MemModule {
    pub base: u64,
    pub size: u32,
    pub full_name: String,
}

/// Everything the image can be made to say about its processes.
pub fn enumerate(mem: &PhysicalMemory, profile: &KernelProfile) -> Result<Vec<MemProcess>> {
    let kernel = AddressSpace::new(mem, profile.kernel_dtb);
    let mut by_pid: BTreeMap<u64, MemProcess> = BTreeMap::new();

    for p in linked(mem, &kernel, profile) {
        by_pid.insert(p.pid, p);
    }

    // The pool scan needs to know where `_EPROCESS` starts relative to the field
    // the profile is anchored on, and that relationship is measured against the
    // processes already found rather than assumed.
    if let Some(base_delta) = eprocess_base_delta(mem, profile, &by_pid) {
        for mut p in scanned(mem, profile, base_delta) {
            match by_pid.get_mut(&p.pid) {
                Some(known) if known.dtb == p.dtb => {
                    known.discovery = Discovery::Both;
                    known.eprocess_pa = p.eprocess_pa;
                }
                // A pool entry whose PID is known but whose address space is
                // not is a different process that reused the number, so it is
                // kept separately rather than folded into the live one.
                _ => {
                    p.discovery = Discovery::Unlinked;
                    by_pid.entry(p.pid).or_insert(p);
                }
            }
        }
    }

    let mut out: Vec<MemProcess> = by_pid.into_values().collect();
    for p in &mut out {
        enrich(mem, p);
    }
    out.sort_by_key(|p| (p.create_time, p.pid));
    Ok(out)
}

fn linked(
    mem: &PhysicalMemory,
    kernel: &AddressSpace,
    profile: &KernelProfile,
) -> Vec<MemProcess> {
    let mut out = Vec::new();
    let mut at = profile.system_apl_va;
    let start = at;

    for _ in 0..65_536 {
        if let Some(p) = read_at_apl(mem, kernel, profile, at) {
            out.push(p);
        }
        let Ok(next) = kernel.read_u64(at) else { break };
        if next == start || !is_kernel_va(next) || next & 7 != 0 {
            break;
        }
        at = next;
    }
    out
}

fn read_at_apl(
    mem: &PhysicalMemory,
    kernel: &AddressSpace,
    profile: &KernelProfile,
    apl_va: u64,
) -> Option<MemProcess> {
    let l = &profile.layout;
    let at = |d: i64| apl_va.wrapping_add(d as u64);

    let pid = kernel.read_u64(at(l.unique_process_id)).ok()?;
    if pid == 0 || pid >= 0x0010_0000 {
        // Also rejects `PsActiveProcessHead`, which sits in kernel data and has
        // no process fields around it.
        return None;
    }
    let dtb = kernel.read_u64(at(l.directory_table_base)).ok()? & 0x0000_FFFF_FFFF_F000;
    if dtb == 0 || !mem.is_mapped(dtb) {
        return None;
    }

    let mut name = [0u8; 15];
    kernel.read_lossy(at(l.image_file_name), &mut name);

    Some(MemProcess {
        pid,
        ppid: kernel.read_u64(at(l.inherited_from_pid)).unwrap_or(0),
        name: image_name(&name),
        dtb,
        create_time: kernel.read_u64(at(l.create_time)).unwrap_or(0),
        exit_time: kernel.read_u64(at(l.exit_time)).unwrap_or(0),
        discovery: Discovery::Linked,
        eprocess_pa: kernel.translate(apl_va).map(|m| m.phys),
        apl_va: Some(apl_va),
        peb_va: l.peb.and_then(|d| kernel.read_u64(at(d)).ok()).filter(|&v| v != 0),
        command_line: None,
        image_path: None,
        current_directory: None,
        modules: Vec::new(),
    })
}

/// Distance from the start of a pool allocation to `ActiveProcessLinks`.
///
/// Measured, not assumed: for processes already found by walking the list we
/// know the exact `DirectoryTableBase` value, so the offset at which that value
/// appears inside a `Proc` allocation identifies the structure's origin. The
/// answer that the most allocations agree on is the right one.
fn eprocess_base_delta(
    mem: &PhysicalMemory,
    profile: &KernelProfile,
    known: &BTreeMap<u64, MemProcess>,
) -> Option<i64> {
    let dtbs: Vec<u64> = known.values().map(|p| p.dtb).collect();
    if dtbs.is_empty() {
        return None;
    }
    let hits = scan::find_pool(mem, b"Proc", 0x300, 0x1000);
    if hits.is_empty() {
        return None;
    }

    let mut votes: BTreeMap<i64, usize> = BTreeMap::new();
    for hit in hits.iter().take(4096) {
        for d in (0..0x80u64).step_by(8) {
            let Ok(v) = mem.read_u64(hit.body_pa + d) else { continue };
            if dtbs.contains(&(v & 0x0000_FFFF_FFFF_F000)) {
                *votes.entry(d as i64).or_default() += 1;
            }
        }
    }
    let (dtb_from_start, count) = votes.into_iter().max_by_key(|&(_, n)| n)?;
    // A single coincidence proves nothing; a repeated one is the layout.
    if count < 2 {
        return None;
    }
    Some(dtb_from_start - profile.layout.directory_table_base)
}

/// Processes found by their pool allocation rather than by the kernel's list.
fn scanned(mem: &PhysicalMemory, profile: &KernelProfile, base_delta: i64) -> Vec<MemProcess> {
    let l = &profile.layout;
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    for hit in scan::find_pool(mem, b"Proc", 0x300, 0x1000) {
        let apl_pa = hit.body_pa.wrapping_add(base_delta as u64);
        let at = |d: i64| apl_pa.wrapping_add(d as u64);

        let Ok(pid) = mem.read_u64(at(l.unique_process_id)) else { continue };
        if pid == 0 || pid >= 0x0010_0000 || pid % 4 != 0 {
            continue;
        }
        let Ok(dtb_raw) = mem.read_u64(at(l.directory_table_base)) else { continue };
        let dtb = dtb_raw & 0x0000_FFFF_FFFF_F000;
        if dtb == 0 || !mem.is_mapped(dtb) {
            continue;
        }
        let create_time = mem.read_u64(at(l.create_time)).unwrap_or(0);
        // A pool allocation that has been handed back and partially overwritten
        // will still carry the tag. Requiring a sane creation date discards
        // those without discarding a genuinely unlinked process, which has no
        // reason to have a corrupt one.
        if create_time != 0 && !(125_911_584_000_000_000..157_469_040_000_000_000).contains(&create_time) {
            continue;
        }

        let mut name = [0u8; 15];
        mem.read_lossy(at(l.image_file_name), &mut name);
        let name = image_name(&name);
        if name.is_empty() {
            continue;
        }
        if !seen.insert((pid, dtb)) {
            continue;
        }

        out.push(MemProcess {
            pid,
            ppid: mem.read_u64(at(l.inherited_from_pid)).unwrap_or(0),
            name,
            dtb,
            create_time,
            exit_time: mem.read_u64(at(l.exit_time)).unwrap_or(0),
            discovery: Discovery::Unlinked,
            eprocess_pa: Some(hit.body_pa),
            apl_va: None,
            peb_va: l.peb.and_then(|d| mem.read_u64(at(d)).ok()).filter(|&v| is_user_va(v)),
            command_line: None,
            image_path: None,
            current_directory: None,
            modules: Vec::new(),
        });
    }
    out
}

/// A fixed-size name field, cut at its terminator and stripped of anything a
/// filename cannot contain.
fn image_name(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    raw[..end]
        .iter()
        .filter(|&&b| (0x20..0x7f).contains(&b))
        .map(|&b| b as char)
        .collect()
}

/// Read what only the process's own address space can tell us.
fn enrich(mem: &PhysicalMemory, p: &mut MemProcess) {
    let Some(peb_va) = p.peb_va else { return };
    let space = AddressSpace::new(mem, p.dtb);

    if let Ok(params) = space.read_u64(peb_va + PEB_PROCESS_PARAMETERS) {
        if is_user_va(params) {
            p.current_directory = unicode_string(&space, params + PARAMS_CURRENT_DIRECTORY);
            p.image_path = unicode_string(&space, params + PARAMS_IMAGE_PATH);
            p.command_line = unicode_string(&space, params + PARAMS_COMMAND_LINE);
        }
    }
    p.modules = modules(&space, peb_va);
}

// User-mode structure offsets. Unlike `_EPROCESS`, these are part of the
// documented ABI that every Windows binary depends on, so they have not moved
// since x64 Windows shipped and do not need calibrating.
const PEB_LDR: u64 = 0x18;
const PEB_PROCESS_PARAMETERS: u64 = 0x20;
const PARAMS_CURRENT_DIRECTORY: u64 = 0x38;
const PARAMS_IMAGE_PATH: u64 = 0x60;
const PARAMS_COMMAND_LINE: u64 = 0x70;
const LDR_IN_LOAD_ORDER: u64 = 0x10;
const ENTRY_DLL_BASE: u64 = 0x30;
const ENTRY_SIZE_OF_IMAGE: u64 = 0x40;
const ENTRY_FULL_NAME: u64 = 0x48;

/// Read a `UNICODE_STRING` and its buffer.
///
/// Partial recovery is deliberate. A command line that is half paged out is
/// still evidence, and returning the half we have beats returning nothing —
/// provided the caller can see that is what happened, which the replacement
/// character makes plain.
fn unicode_string(space: &AddressSpace, at: u64) -> Option<String> {
    let length = space.read_u16(at).ok()?;
    let maximum = space.read_u16(at + 2).ok()?;
    let buffer = space.read_u64(at + 8).ok()?;
    if length == 0 || length > maximum || length % 2 != 0 || !is_user_va(buffer) {
        return None;
    }
    // A pathological length would otherwise let a corrupt structure ask for an
    // arbitrarily large allocation.
    let want = (length as usize).min(0x8000);
    let mut bytes = vec![0u8; want];
    let got = space.read_lossy(buffer, &mut bytes);
    if got == 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let s: String = char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .filter(|&c| c != '\0')
        .collect();
    (!s.is_empty()).then_some(s)
}

fn modules(space: &AddressSpace, peb_va: u64) -> Vec<MemModule> {
    let Ok(ldr) = space.read_u64(peb_va + PEB_LDR) else { return Vec::new() };
    if !is_user_va(ldr) {
        return Vec::new();
    }
    let head = ldr + LDR_IN_LOAD_ORDER;
    let Ok(first) = space.read_u64(head) else { return Vec::new() };

    let mut out = Vec::new();
    let mut at = first;
    for _ in 0..1024 {
        if at == head || !is_user_va(at) {
            break;
        }
        let base = space.read_u64(at + ENTRY_DLL_BASE).unwrap_or(0);
        let size = space.read_u32(at + ENTRY_SIZE_OF_IMAGE).unwrap_or(0);
        if let Some(full_name) = unicode_string(space, at + ENTRY_FULL_NAME) {
            if base != 0 {
                out.push(MemModule { base, size, full_name });
            }
        }
        let Ok(next) = space.read_u64(at) else { break };
        if next == at {
            break;
        }
        at = next;
    }
    out
}
