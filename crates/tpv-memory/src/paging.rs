//! IA-32e (x86-64 long mode) address translation.
//!
//! This is the layer that turns a memory image from a pile of pages into an
//! address space. Everything above it — walking the process list, reading a
//! PEB, recovering a command line — is expressed in virtual addresses, because
//! that is how the operating system wrote them down.
//!
//! Two details are worth stating because getting either wrong produces plausible
//! but wrong output rather than an error:
//!
//! * Large pages. A PDPT entry with PS set maps a 1 GiB page and a PD entry with
//!   PS set maps a 2 MiB page. The kernel maps itself with large pages, so a
//!   walker that always descends four levels fails on precisely the addresses
//!   most worth reading.
//! * Transition pages. When Windows trims a page it clears Present but keeps the
//!   frame number and sets the Transition bit. The page is still in RAM and its
//!   contents are still there. Honouring transition entries recovers a
//!   meaningful share of a process's memory that a strict walker reports as
//!   paged out — including, often, the command line.

use crate::error::{MemoryError, Result};
use crate::image::PhysicalMemory;

const PRESENT: u64 = 1 << 0;
const LARGE: u64 = 1 << 7;
const PROTOTYPE: u64 = 1 << 10;
const TRANSITION: u64 = 1 << 11;
/// Bits 12..=51 of an entry hold the frame number.
const PFN_MASK: u64 = 0x0000_FFFF_FFFF_F000;

pub const PAGE_SIZE: u64 = 0x1000;
const LARGE_2M: u64 = 0x20_0000;
const LARGE_1G: u64 = 0x4000_0000;

/// How a virtual address resolved, kept because "present" and "recovered from a
/// transition page" are different claims about the same bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Residency {
    Present,
    /// Trimmed but still resident; the contents are real but the process was no
    /// longer actively using the page.
    Transition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    pub phys: u64,
    /// Bytes remaining in the mapped page from `phys`, which is up to 1 GiB when
    /// a large page backs the address.
    pub run: u64,
    pub residency: Residency,
}

/// A virtual address space: an image plus the page-table root to read it with.
#[derive(Clone, Copy)]
pub struct AddressSpace<'a> {
    mem: &'a PhysicalMemory,
    dtb: u64,
}

impl<'a> AddressSpace<'a> {
    pub fn new(mem: &'a PhysicalMemory, dtb: u64) -> Self {
        // The low bits of CR3 carry PCID and flags, never part of the address.
        Self { mem, dtb: dtb & PFN_MASK }
    }

    pub fn dtb(&self) -> u64 {
        self.dtb
    }

    pub fn physical(&self) -> &'a PhysicalMemory {
        self.mem
    }

    /// Resolve one virtual address.
    pub fn translate(&self, va: u64) -> Option<Mapping> {
        let pml4e = self.entry(self.dtb, index(va, 39))?;
        if pml4e & PRESENT == 0 {
            return None;
        }

        let pdpte = self.entry(pml4e & PFN_MASK, index(va, 30))?;
        if pdpte & PRESENT == 0 {
            return None;
        }
        if pdpte & LARGE != 0 {
            let base = pdpte & 0x0000_FFFF_C000_0000;
            let off = va & (LARGE_1G - 1);
            return Some(Mapping {
                phys: base + off,
                run: LARGE_1G - off,
                residency: Residency::Present,
            });
        }

        let pde = self.entry(pdpte & PFN_MASK, index(va, 21))?;
        if pde & PRESENT == 0 {
            return None;
        }
        if pde & LARGE != 0 {
            let base = pde & 0x0000_FFFF_FFE0_0000;
            let off = va & (LARGE_2M - 1);
            return Some(Mapping {
                phys: base + off,
                run: LARGE_2M - off,
                residency: Residency::Present,
            });
        }

        let pte = self.entry(pde & PFN_MASK, index(va, 12))?;
        let off = va & (PAGE_SIZE - 1);
        let residency = if pte & PRESENT != 0 {
            Residency::Present
        } else if pte & TRANSITION != 0 && pte & PROTOTYPE == 0 {
            Residency::Transition
        } else {
            return None;
        };
        let phys = (pte & PFN_MASK) + off;
        Some(Mapping { phys, run: PAGE_SIZE - off, residency })
    }

    fn entry(&self, table: u64, i: u64) -> Option<u64> {
        self.mem.read_u64(table + i * 8).ok()
    }

    /// Fill `buf` from virtual memory, or fail at the first unmapped page.
    pub fn read(&self, va: u64, buf: &mut [u8]) -> Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let at = va + done as u64;
            let m = self
                .translate(at)
                .ok_or(MemoryError::NotTranslated { addr: at, dtb: self.dtb })?;
            let want = (buf.len() - done).min(m.run as usize);
            let src = self
                .mem
                .slice_at(m.phys)
                .ok_or(MemoryError::NotMapped(m.phys))?;
            let n = want.min(src.len());
            if n == 0 {
                return Err(MemoryError::NotMapped(m.phys));
            }
            buf[done..done + n].copy_from_slice(&src[..n]);
            done += n;
        }
        Ok(())
    }

    /// Read what translates, zero-filling the rest, and report how many bytes
    /// were real. A partly paged-out string is still worth showing as long as
    /// the caller knows which part was recovered.
    pub fn read_lossy(&self, va: u64, buf: &mut [u8]) -> usize {
        let mut done = 0usize;
        let mut got = 0usize;
        while done < buf.len() {
            let at = va + done as u64;
            let step = match self.translate(at) {
                Some(m) => {
                    let want = (buf.len() - done).min(m.run as usize);
                    match self.mem.slice_at(m.phys) {
                        Some(src) => {
                            let n = want.min(src.len());
                            buf[done..done + n].copy_from_slice(&src[..n]);
                            got += n;
                            n.max(1)
                        }
                        None => skip_to_next_page(at, buf.len() - done),
                    }
                }
                None => skip_to_next_page(at, buf.len() - done),
            };
            done += step;
        }
        got
    }

    pub fn read_u64(&self, va: u64) -> Result<u64> {
        let mut b = [0u8; 8];
        self.read(va, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    pub fn read_u32(&self, va: u64) -> Result<u32> {
        let mut b = [0u8; 4];
        self.read(va, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    pub fn read_u16(&self, va: u64) -> Result<u16> {
        let mut b = [0u8; 2];
        self.read(va, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }

    pub fn is_mapped(&self, va: u64) -> bool {
        self.translate(va).is_some()
    }
}

/// Bytes to advance to reach the next page boundary, bounded by what is left.
fn skip_to_next_page(at: u64, remaining: usize) -> usize {
    let to_boundary = PAGE_SIZE - (at & (PAGE_SIZE - 1));
    (to_boundary as usize).min(remaining).max(1)
}

fn index(va: u64, shift: u32) -> u64 {
    (va >> shift) & 0x1ff
}

/// Canonical kernel-half address on x86-64.
///
/// Used everywhere a candidate pointer has to be judged before it is followed;
/// a non-canonical value is one that no CPU could have loaded, so it is a cheap
/// and total rejection of a bad guess.
pub fn is_kernel_va(va: u64) -> bool {
    va >= 0xFFFF_8000_0000_0000
}

/// Canonical user-half address, excluding null and the lowest page.
pub fn is_user_va(va: u64) -> bool {
    va >= PAGE_SIZE && va < 0x0000_8000_0000_0000
}
