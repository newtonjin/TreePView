//! Scanning the physical layer for byte patterns.
//!
//! Used for two things: locating anchor structures whose contents we can predict
//! (the `System` process name), and pool-tag scanning, which finds objects the
//! kernel has already unlinked from its own lists. The second is why scanning
//! earns its cost — a process removed from `ActiveProcessLinks` to hide it still
//! sits in a pool allocation with its tag intact.

use crate::image::PhysicalMemory;

/// Physical addresses where `needle` occurs, respecting an alignment.
///
/// Alignment is not an optimisation. Kernel structures are allocated aligned,
/// so an unaligned hit is by definition not the structure being looked for, and
/// dropping those removes most of the false positives before they cost anything
/// to validate.
pub fn find_all(mem: &PhysicalMemory, needle: &[u8], align: u64) -> Vec<u64> {
    let finder = memchr::memmem::Finder::new(needle);
    let mut hits = Vec::new();
    for run in mem.runs() {
        let Some(bytes) = mem.slice_at(run.phys) else { continue };
        let bytes = &bytes[..(run.len as usize).min(bytes.len())];
        for at in finder.find_iter(bytes) {
            let pa = run.phys + at as u64;
            if pa % align == 0 {
                hits.push(pa);
            }
        }
    }
    hits
}

/// A pool allocation found by its tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolHit {
    /// Physical address of the tag itself.
    pub tag_pa: u64,
    /// Physical address of the body that follows the pool header.
    pub body_pa: u64,
    /// Bytes the header says the allocation occupies.
    pub size: u64,
}

/// `_POOL_HEADER` on x64 is 16 bytes and ends with the four-character tag, so a
/// tag hit implies a header 12 bytes earlier and a body 4 bytes later.
const POOL_HEADER: u64 = 0x10;
const POOL_TAG_OFFSET: u64 = 0x0c;
/// `PoolHeader.BlockSize` counts 16-byte units.
const POOL_GRANULARITY: u64 = 0x10;

/// Every allocation carrying `tag`, with the obviously impossible ones dropped.
///
/// The size sanity check matters more than it looks: a four-byte tag occurs by
/// chance roughly once per four gigabytes of unrelated data, and without a
/// second constraint the caller ends up validating thousands of positions that
/// were never allocations at all.
pub fn find_pool(mem: &PhysicalMemory, tag: &[u8; 4], min_body: u64, max_body: u64) -> Vec<PoolHit> {
    let mut out = Vec::new();
    for tag_pa in find_all(mem, tag, 1) {
        if tag_pa < POOL_TAG_OFFSET {
            continue;
        }
        let header_pa = tag_pa - POOL_TAG_OFFSET;
        if header_pa % POOL_GRANULARITY != 0 {
            continue;
        }
        let Ok(raw) = mem.read_u32(header_pa) else { continue };
        // PreviousSize:8, PoolIndex:8, BlockSize:8, PoolType:8 on x64.
        let block_size = ((raw >> 16) & 0xff) as u64;
        let size = block_size * POOL_GRANULARITY;
        if size < min_body + POOL_HEADER || size > max_body + POOL_HEADER {
            continue;
        }
        out.push(PoolHit { tag_pa, body_pa: header_pa + POOL_HEADER, size });
    }
    out
}
