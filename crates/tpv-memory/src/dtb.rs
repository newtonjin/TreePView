//! Finding a page-table root in an image that came with no metadata.
//!
//! Analysis cannot begin until we have a directory table base, and a raw capture
//! does not record CR3 anywhere. What it does contain is the page tables
//! themselves, and a PML4 is a highly distinctive object: 512 eight-byte entries
//! whose reserved bits are zero, and — on Windows — one entry that points back
//! at the table it lives in, the self-map the kernel installs so it can edit its
//! own page tables through a fixed virtual window.
//!
//! That self-reference is the signature. It is index 0x1ED on Windows up to
//! 1511 and randomised from 1607 onwards, so this looks for the property rather
//! than the position, which makes it version-independent by construction.
//!
//! Several processes' roots will match. They are ranked rather than filtered:
//! the System process is the one with the kernel mapped and almost no user half,
//! and that is the address space the process list lives in.

use crate::image::PhysicalMemory;

/// A page that behaves like a page-table root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtbCandidate {
    pub dtb: u64,
    /// Present entries in the upper half, which is the kernel.
    pub kernel_entries: u32,
    /// Present entries in the lower half, which is whatever process owns it.
    pub user_entries: u32,
    /// Index of the entry pointing back at this table.
    pub self_index: u16,
}

/// Rank of a candidate as *the kernel's* address space: kernel mappings present,
/// user mappings absent. Lower sorts first.
fn rank(c: &DtbCandidate) -> (u32, i64) {
    // The System process has no user address space to speak of. Ordinary
    // processes share the same kernel half, so the user half is what separates
    // them, and a handful of entries is tolerated because the kernel keeps a
    // small shared low mapping on some builds.
    (c.user_entries, -(c.kernel_entries as i64))
}

/// Every plausible page-table root, best first.
///
/// Ordered rather than reduced to one answer because the ranking is a heuristic
/// and the real confirmation is downstream: a root is correct when the process
/// list walks cleanly through it. Handing back an ordered list lets that
/// confirmation drive the choice instead of this function guessing.
pub fn candidates(mem: &PhysicalMemory) -> Vec<DtbCandidate> {
    let mut found = Vec::new();
    for pa in mem.pages() {
        if let Some(c) = inspect(mem, pa) {
            found.push(c);
        }
    }
    found.sort_by_key(rank);
    found
}

/// As `candidates`, but stops once `want` roots that look like the kernel's have
/// been seen. On a large image this turns a full scan into an early exit.
pub fn candidates_capped(mem: &PhysicalMemory, want: usize) -> Vec<DtbCandidate> {
    let mut found = Vec::new();
    let mut strong = 0usize;
    for pa in mem.pages() {
        if let Some(c) = inspect(mem, pa) {
            if c.user_entries == 0 && c.kernel_entries >= 8 {
                strong += 1;
            }
            found.push(c);
            if strong >= want {
                break;
            }
        }
    }
    found.sort_by_key(rank);
    found
}

const PRESENT: u64 = 1 << 0;
const PFN_MASK: u64 = 0x0000_FFFF_FFFF_F000;
/// Bits 52..=62 are reserved in a 4-level paging entry; bit 63 is NX.
const RESERVED_MASK: u64 = 0x7FF0_0000_0000_0000;

fn inspect(mem: &PhysicalMemory, pa: u64) -> Option<DtbCandidate> {
    let page = mem.slice_at(pa)?;
    if page.len() < 0x1000 {
        return None;
    }

    let mut self_index = None;
    let mut kernel_entries = 0u32;
    let mut user_entries = 0u32;

    for (i, chunk) in page[..0x1000].chunks_exact(8).enumerate() {
        let e = u64::from_le_bytes(chunk.try_into().ok()?);
        if e & PRESENT == 0 {
            // A cleared entry is normal. A non-zero entry with Present clear is
            // not something a PML4 contains, and rejecting it removes most of
            // the data pages that would otherwise pass by coincidence.
            if e != 0 {
                return None;
            }
            continue;
        }
        if e & RESERVED_MASK != 0 {
            return None;
        }
        let target = e & PFN_MASK;
        if target == pa {
            self_index = Some(i as u16);
        }
        if i >= 256 {
            kernel_entries += 1;
        } else {
            user_entries += 1;
        }
    }

    // The self-map is a kernel-only window, so its index is always in the upper
    // half. A page whose only self-reference is below the split is a page that
    // happens to contain its own address, not a page-table root.
    let self_index = self_index.filter(|&i| i >= 256)?;
    // A root with nothing above the split is not an x64 Windows address space;
    // every process shares the kernel half.
    if kernel_entries == 0 {
        return None;
    }
    Some(DtbCandidate { dtb: pa, kernel_entries, user_entries, self_index })
}
