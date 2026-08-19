//! Recovering the `_EPROCESS` layout from the image itself.
//!
//! Volatility solves this problem with symbol tables: it identifies the exact
//! kernel build, fetches the matching debug symbols, and reads field offsets out
//! of them. That is precise, and it is also why it needs a network connection, a
//! symbol cache, and a matching profile for every Windows build ever shipped.
//!
//! This module takes the other route. Rather than being told where the fields
//! are, it works them out by testing hypotheses against the image until only one
//! survives. The technique rests on a single anchor and a chain of constraints:
//!
//! 1. The `System` process is always present and its `ImageFileName` always
//!    contains the bytes `System`. Scanning for that gives a small set of
//!    candidate structures.
//! 2. `ActiveProcessLinks` is a doubly linked list. For a real entry,
//!    `Flink->Blink` and `Blink->Flink` both point back at the entry itself.
//!    That round trip, checked through the page tables, is a test almost no
//!    coincidence survives, and it locates the field exactly.
//! 3. Every remaining offset is then pinned by something already known.
//!    `DirectoryTableBase` must equal the page-table root we walked the list
//!    with. `UniqueProcessId` must be 4 for System and a valid process id for
//!    everything else. `CreateTime` must be a plausible date for most entries
//!    and the earliest one for System. `InheritedFromUniqueProcessId` must name
//!    a process that is actually in the list.
//!
//! The result is a layout derived from evidence rather than assumed, which means
//! it works on builds that did not exist when this was written, and — more
//! importantly — it fails loudly instead of quietly reading the wrong field when
//! it does not work.

use crate::dtb::DtbCandidate;
use crate::error::{MemoryError, Result};
use crate::image::PhysicalMemory;
use crate::paging::{is_kernel_va, is_user_va, AddressSpace};
use crate::scan;

/// Field positions, all relative to `ActiveProcessLinks`.
///
/// Anchored on that field rather than on the start of the structure because it
/// is the only one that can be located outright; where `_EPROCESS` actually
/// begins is never needed and is not guessed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct EprocessLayout {
    pub image_file_name: i64,
    pub unique_process_id: i64,
    pub inherited_from_pid: i64,
    pub directory_table_base: i64,
    pub create_time: i64,
    pub exit_time: i64,
    pub peb: Option<i64>,
}

/// A calibrated view of one kernel, with the evidence behind it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KernelProfile {
    pub layout: EprocessLayout,
    pub kernel_dtb: u64,
    /// Virtual address of the `System` process's `ActiveProcessLinks`.
    pub system_apl_va: u64,
    /// Entries reachable by walking the list, including the list head.
    pub linked_entries: usize,
    /// Share of those entries whose fields validated, as a percentage. Anything
    /// short of the high nineties means the layout is suspect and the output
    /// should be read with that in mind.
    pub agreement: u8,
}

const FILETIME_2000: u64 = 125_911_584_000_000_000;
const FILETIME_2100: u64 = 157_469_040_000_000_000;
const PFN_MASK: u64 = 0x0000_FFFF_FFFF_F000;
/// Windows will not hand out a process id above this, and every id is a
/// multiple of four.
const MAX_PID: u64 = 0x0010_0000;

/// The `System` process name as it sits in a fixed-size field, with enough
/// trailing NULs that ordinary occurrences of the word do not match.
const SYSTEM_NEEDLE: &[u8] = b"System\0\0\0";

/// Work out the layout, trying page-table roots until one yields a process list.
///
/// The roots arrive ranked by how much they look like the kernel's, but ranking
/// is a guess and walking the list is proof, so every candidate gets tried
/// rather than trusting the first.
pub fn calibrate(mem: &PhysicalMemory, roots: &[DtbCandidate]) -> Result<KernelProfile> {
    let name_hits = scan::find_all(mem, SYSTEM_NEEDLE, 8);
    if name_hits.is_empty() {
        return Err(MemoryError::NoProcessList(
            "no System process name was found; the image may be encrypted, compressed, \
             or not a Windows capture"
                .into(),
        ));
    }

    let mut best: Option<KernelProfile> = None;
    for root in roots.iter().take(24) {
        let space = AddressSpace::new(mem, root.dtb);
        for &name_pa in &name_hits {
            let Some(anchor) = anchor_at(mem, &space, name_pa) else { continue };
            let Some(profile) = build(mem, &space, &anchor) else { continue };
            // An exact agreement cannot be improved on, so stop rather than
            // spend a full scan confirming what is already certain.
            if profile.agreement >= 99 {
                return Ok(profile);
            }
            if best.as_ref().is_none_or(|b| b.agreement < profile.agreement) {
                best = Some(profile);
            }
        }
    }

    best.ok_or_else(|| {
        MemoryError::NoProcessList(
            "found the System process name but no consistent ActiveProcessLinks near it; \
             the capture may be too inconsistent to walk"
                .into(),
        )
    })
}

/// A located `ActiveProcessLinks`, and where the name sits relative to it.
struct Anchor {
    apl_va: u64,
    name_delta: i64,
}

/// Test every plausible distance between a name hit and a list entry.
///
/// `ActiveProcessLinks` precedes `ImageFileName` in every x64 `_EPROCESS`
/// shipped, but by a distance that moved with almost every release, so the
/// distance is searched rather than assumed.
fn anchor_at(mem: &PhysicalMemory, space: &AddressSpace, name_pa: u64) -> Option<Anchor> {
    for delta in (8..=0x400u64).step_by(8) {
        if delta > name_pa {
            break;
        }
        let apl_pa = name_pa - delta;
        if let Some(apl_va) = round_trips(mem, space, apl_pa) {
            return Some(Anchor { apl_va, name_delta: delta as i64 });
        }
    }
    None
}

/// True when the two pointers at `apl_pa` behave like a linked list entry.
///
/// Both neighbours must point back here, checked by translating their pointers
/// and comparing physical addresses, so the check survives the same structure
/// being reachable through more than one virtual address.
fn round_trips(mem: &PhysicalMemory, space: &AddressSpace, apl_pa: u64) -> Option<u64> {
    let flink = mem.read_u64(apl_pa).ok()?;
    let blink = mem.read_u64(apl_pa + 8).ok()?;
    if !is_kernel_va(flink) || !is_kernel_va(blink) || flink & 7 != 0 || blink & 7 != 0 {
        return None;
    }

    let flink_pa = space.translate(flink)?.phys;
    let back = mem.read_u64(flink_pa + 8).ok()?;
    if !is_kernel_va(back) || space.translate(back)?.phys != apl_pa {
        return None;
    }

    let blink_pa = space.translate(blink)?.phys;
    let forward = mem.read_u64(blink_pa).ok()?;
    if !is_kernel_va(forward) || space.translate(forward)?.phys != apl_pa {
        return None;
    }

    Some(back)
}

/// Follow `Flink` all the way round, returning every entry once.
///
/// One of them is `PsActiveProcessHead`, which is a bare list head in kernel
/// data and not part of any `_EPROCESS`. It cannot be told apart structurally,
/// so it is left in and the field validators are written to tolerate a single
/// entry that makes no sense.
fn walk(space: &AddressSpace, start_va: u64, limit: usize) -> Vec<u64> {
    let mut out = Vec::new();
    let mut at = start_va;
    for _ in 0..limit {
        out.push(at);
        let Ok(next) = space.read_u64(at) else { break };
        if next == start_va || !is_kernel_va(next) || next & 7 != 0 {
            break;
        }
        at = next;
    }
    out
}

fn build(mem: &PhysicalMemory, space: &AddressSpace, anchor: &Anchor) -> Option<KernelProfile> {
    let entries = walk(space, anchor.apl_va, 65_536);
    // Two entries would be the System process and the list head, which is a real
    // state on a machine that has just booted but is not enough to calibrate
    // against: every offset would be confirmed by a single sample.
    if entries.len() < 4 {
        return None;
    }

    let read = |va: u64, d: i64| -> Option<u64> { space.read_u64(offset(va, d)).ok() };

    let pid = find_offset(-0x80, 0, |d| {
        if read(anchor.apl_va, d) != Some(4) {
            return None;
        }
        Some(agreement(&entries, |va| read(va, d).is_some_and(plausible_pid)))
    })?;

    let dtb = find_offset(-0x800, 0, |d| {
        if read(anchor.apl_va, d)? & PFN_MASK != space.dtb() {
            return None;
        }
        Some(agreement(&entries, |va| {
            read(va, d).is_some_and(|v| plausible_dtb(mem, v))
        }))
    })?;

    let create_time = find_offset(-0x100, 0, |d| {
        let system = read(anchor.apl_va, d)?;
        if !plausible_filetime(system) {
            return None;
        }
        // System is the first process the kernel creates, so nothing in the list
        // may predate it. This is what separates CreateTime from the several
        // other 64-bit fields that happen to hold plausible dates.
        let earliest = entries
            .iter()
            .filter_map(|&va| read(va, d))
            .filter(|&v| plausible_filetime(v))
            .min()?;
        if earliest < system {
            return None;
        }
        Some(agreement(&entries, |va| {
            read(va, d).is_some_and(plausible_filetime)
        }))
    })?;

    // ExitTime directly follows CreateTime in every version, and the check that
    // matters is that it is empty for most entries: a list of mostly running
    // processes cannot be mostly exited.
    let exit_time = create_time + 8;
    if agreement(&entries, |va| read(va, exit_time) == Some(0)) < 50 {
        return None;
    }

    let known_pids: Vec<u64> = entries
        .iter()
        .filter_map(|&va| read(va, pid))
        .filter(|&v| plausible_pid(v))
        .collect();

    let inherited_from_pid = find_offset(8, 0x300, |d| {
        let score = agreement(&entries, |va| {
            read(va, d).is_some_and(|v| plausible_pid(v) && known_pids.contains(&v))
        });
        // Half the list naming a process that is also in the list is far beyond
        // chance, and it has to be a proportion rather than all of them because
        // parents legitimately exit and disappear.
        (score >= 50).then_some(score)
    })?;

    // The `Peb` field cannot be scored the way the others are. A run of zeroed
    // padding satisfies "every entry is either empty or valid" perfectly, so a
    // proportion would happily settle on the first hole in the structure. What
    // identifies the real field is the *count* of entries holding a pointer that
    // behaves like a PEB, combined with no entry holding something that could
    // not be one — so the score here is that count, and the offset with the most
    // confirmations wins.
    let peb = find_offset(8, 0x400, |d| {
        let mut confirmed = 0usize;
        for &va in &entries {
            let Some(value) = read(va, d) else { continue };
            if value == 0 {
                // Kernel-only processes genuinely have no user address space.
                continue;
            }
            if !is_user_va(value) {
                return None;
            }
            let Some(process_dtb) = read(va, dtb) else { return None };
            if !looks_like_peb(mem, process_dtb & PFN_MASK, value) {
                return None;
            }
            confirmed += 1;
        }
        // Two independent confirmations, each requiring a user pointer whose
        // target holds another valid user pointer at the right offset, is
        // already far past coincidence. Demanding more would quietly discard
        // every command line on a host with few user processes, which is the
        // worst possible way to fail.
        (confirmed >= 2).then(|| confirmed.min(255) as u8)
    });

    let layout = EprocessLayout {
        image_file_name: anchor.name_delta,
        unique_process_id: pid,
        inherited_from_pid,
        directory_table_base: dtb,
        create_time,
        exit_time,
        peb,
    };

    let agreement = [
        agreement(&entries, |va| read(va, pid).is_some_and(plausible_pid)),
        agreement(&entries, |va| {
            read(va, dtb).is_some_and(|v| plausible_dtb(mem, v))
        }),
        agreement(&entries, |va| {
            read(va, create_time).is_some_and(plausible_filetime)
        }),
    ]
    .into_iter()
    .min()
    .unwrap_or(0);

    Some(KernelProfile {
        layout,
        kernel_dtb: space.dtb(),
        system_apl_va: anchor.apl_va,
        linked_entries: entries.len(),
        agreement,
    })
}

/// Try every eight-byte-aligned offset in a window, keeping the best-scoring.
fn find_offset(from: i64, to: i64, score: impl Fn(i64) -> Option<u8>) -> Option<i64> {
    let mut best: Option<(u8, i64)> = None;
    let mut d = from;
    while d < to {
        if let Some(s) = score(d) {
            if best.is_none_or(|(bs, _)| s > bs) {
                best = Some((s, d));
            }
        }
        d += 8;
    }
    best.map(|(_, d)| d)
}

/// Percentage of entries satisfying a predicate.
fn agreement(entries: &[u64], ok: impl Fn(u64) -> bool) -> u8 {
    if entries.is_empty() {
        return 0;
    }
    let hits = entries.iter().filter(|&&va| ok(va)).count();
    ((hits * 100) / entries.len()) as u8
}

fn offset(va: u64, d: i64) -> u64 {
    va.wrapping_add(d as u64)
}

fn plausible_pid(v: u64) -> bool {
    v != 0 && v < MAX_PID && v % 4 == 0
}

fn plausible_filetime(v: u64) -> bool {
    (FILETIME_2000..FILETIME_2100).contains(&v)
}

fn plausible_dtb(mem: &PhysicalMemory, v: u64) -> bool {
    v != 0 && v & 0xfff == 0 && v < mem.highest_address() && mem.is_mapped(v)
}

/// Whether a candidate PEB address behaves like one.
///
/// Reading the field is not enough — plenty of pointers translate. A PEB is
/// recognised by `ProcessParameters` at 0x20, which is itself a user pointer
/// into the process heap, and that pair of constraints is not met by accident.
fn looks_like_peb(mem: &PhysicalMemory, process_dtb: u64, peb_va: u64) -> bool {
    if !is_user_va(peb_va) {
        return false;
    }
    let space = AddressSpace::new(mem, process_dtb);
    let Ok(params) = space.read_u64(peb_va + 0x20) else { return false };
    is_user_va(params) && space.is_mapped(params)
}
