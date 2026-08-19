//! The physical layer: a memory image as a sparse map of physical addresses.
//!
//! Every acquisition tool writes something slightly different, but they all
//! describe the same thing — which physical page ranges were captured and where
//! each one sits in the file. Normalising that into a run list up front means
//! nothing above this module has to know whether it is reading a crash dump, a
//! LiME capture or a flat `dd`.
//!
//! Ranges matter more than they look. A flat image is not a flat address space:
//! the memory hole below 1 MiB and the PCI hole under 4 GiB are absent on every
//! real machine, and a reader that assumes `file_offset == physical_address`
//! will silently return firmware-mapped rubbish as though it were RAM.

use std::fs::File;
use std::path::{Path, PathBuf};

use crate::error::{MemoryError, Result};

/// A contiguous captured range: `len` bytes of physical memory starting at
/// `phys`, stored at `file` in the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Run {
    pub phys: u64,
    pub file: u64,
    pub len: u64,
}

impl Run {
    fn contains(&self, pa: u64) -> bool {
        pa >= self.phys && pa - self.phys < self.len
    }
}

/// How the image was laid out, kept so the case can record what was parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ImageFormat {
    /// A flat capture: `dd`, `winpmem --format raw`, VMware `.vmem`, VirtualBox
    /// `.sav` payloads, and most hypervisor snapshots.
    Raw,
    /// Windows kernel crash dump, 64-bit variant.
    CrashDump64,
    /// LiME, the usual Linux acquisition format.
    Lime,
    /// An ELF64 core, as produced by QEMU `dump-guest-memory` and several
    /// hypervisor exporters.
    ElfCore,
}

impl ImageFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            ImageFormat::Raw => "raw",
            ImageFormat::CrashDump64 => "crashdump64",
            ImageFormat::Lime => "lime",
            ImageFormat::ElfCore => "elf64-core",
        }
    }
}

enum Backing {
    Mapped(memmap2::Mmap),
    Owned(Vec<u8>),
}

impl Backing {
    fn as_slice(&self) -> &[u8] {
        match self {
            Backing::Mapped(m) => m,
            Backing::Owned(v) => v,
        }
    }
}

/// A memory image, addressed physically.
pub struct PhysicalMemory {
    backing: Backing,
    runs: Vec<Run>,
    format: ImageFormat,
    path: Option<PathBuf>,
}

impl PhysicalMemory {
    /// Map an image from disk and work out its layout.
    ///
    /// Mapped rather than read: these files are commonly the size of the host's
    /// RAM and frequently larger than the analyst's, and scanning wants random
    /// access over the whole thing.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)?;
        // Safety: the image is evidence and is opened read-only. A concurrent
        // writer would be a violation of the analyst's own procedure, and no
        // amount of API design here can prevent that.
        let map = unsafe { memmap2::Mmap::map(&file)? };
        let (format, runs) = layout(&map, &path)?;
        Ok(Self { backing: Backing::Mapped(map), runs, format, path: Some(path) })
    }

    /// Build an image from bytes already in memory. Used by tests, which
    /// synthesise images rather than depending on captures that cannot be
    /// committed to a repository.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let dummy = PathBuf::from("<memory>");
        let (format, runs) = layout(&bytes, &dummy)?;
        Ok(Self { backing: Backing::Owned(bytes), runs, format, path: None })
    }

    /// Treat bytes as a flat capture, skipping format sniffing.
    pub fn raw_from_bytes(bytes: Vec<u8>) -> Self {
        let runs = vec![Run { phys: 0, file: 0, len: bytes.len() as u64 }];
        Self { backing: Backing::Owned(bytes), runs, format: ImageFormat::Raw, path: None }
    }

    /// The file bytes, including format headers. ELF notes live here rather
    /// than in the physical run list.
    pub fn as_bytes(&self) -> &[u8] {
        self.backing.as_slice()
    }

    pub fn format(&self) -> ImageFormat {
        self.format
    }

    pub fn runs(&self) -> &[Run] {
        &self.runs
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Total captured bytes, which is not the same as the highest address.
    pub fn captured_bytes(&self) -> u64 {
        self.runs.iter().map(|r| r.len).sum()
    }

    pub fn highest_address(&self) -> u64 {
        self.runs.iter().map(|r| r.phys + r.len).max().unwrap_or(0)
    }

    /// The largest slice available at `pa` without crossing a run boundary.
    ///
    /// Returning a borrowed slice rather than copying is what makes scanning
    /// gigabytes viable.
    pub fn slice_at(&self, pa: u64) -> Option<&[u8]> {
        let run = self.runs.iter().find(|r| r.contains(pa))?;
        let within = pa - run.phys;
        let start = (run.file + within) as usize;
        let end = (run.file + run.len) as usize;
        let bytes = self.backing.as_slice();
        if start >= bytes.len() {
            return None;
        }
        Some(&bytes[start..end.min(bytes.len())])
    }

    /// Fill `buf` from physical memory, following runs across boundaries.
    pub fn read(&self, pa: u64, buf: &mut [u8]) -> Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let at = pa + done as u64;
            let src = self.slice_at(at).ok_or(MemoryError::NotMapped(at))?;
            let n = src.len().min(buf.len() - done);
            buf[done..done + n].copy_from_slice(&src[..n]);
            done += n;
        }
        Ok(())
    }

    /// Read what is available, reporting how much. Regions that were never
    /// captured read as zero, matching what the analyst would see in any other
    /// tool, but the count lets a caller tell "zeroed" from "absent".
    pub fn read_lossy(&self, pa: u64, buf: &mut [u8]) -> usize {
        let mut done = 0usize;
        let mut got = 0usize;
        while done < buf.len() {
            let at = pa + done as u64;
            match self.slice_at(at) {
                Some(src) => {
                    let n = src.len().min(buf.len() - done);
                    buf[done..done + n].copy_from_slice(&src[..n]);
                    done += n;
                    got += n;
                }
                None => {
                    buf[done] = 0;
                    done += 1;
                }
            }
        }
        got
    }

    pub fn read_u64(&self, pa: u64) -> Result<u64> {
        let mut b = [0u8; 8];
        self.read(pa, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    pub fn read_u32(&self, pa: u64) -> Result<u32> {
        let mut b = [0u8; 4];
        self.read(pa, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    pub fn is_mapped(&self, pa: u64) -> bool {
        self.runs.iter().any(|r| r.contains(pa))
    }

    /// Every captured page, aligned, for scanners to walk.
    pub fn pages(&self) -> impl Iterator<Item = u64> + '_ {
        self.runs.iter().flat_map(|r| {
            let start = (r.phys + 0xfff) & !0xfff;
            let end = r.phys + r.len;
            (start..end).step_by(0x1000)
        })
    }
}

const PAGE: u64 = 0x1000;

fn layout(bytes: &[u8], path: &Path) -> Result<(ImageFormat, Vec<Run>)> {
    if let Some(runs) = crash_dump_64(bytes)? {
        return Ok((ImageFormat::CrashDump64, runs));
    }
    if let Some(runs) = lime(bytes) {
        return Ok((ImageFormat::Lime, runs));
    }
    if let Some(runs) = elf_core(bytes) {
        return Ok((ImageFormat::ElfCore, runs));
    }
    if bytes.is_empty() {
        return Err(MemoryError::UnknownFormat {
            path: path.to_path_buf(),
            reason: "the file is empty".into(),
        });
    }
    Ok((ImageFormat::Raw, vec![Run { phys: 0, file: 0, len: bytes.len() as u64 }]))
}

/// Windows 64-bit crash dump.
///
/// Layout that matters: `"PAGEDU64"` at 0, a `_PHYSICAL_MEMORY_DESCRIPTOR` at
/// 0x88 giving the captured page runs, and the pages themselves packed from
/// 0x2000 in run order. The runs are in pages, not bytes, and they are what
/// makes a dump sparse: skipping them and treating the body as flat shifts
/// every address after the first hole.
fn crash_dump_64(b: &[u8]) -> Result<Option<Vec<Run>>> {
    if b.len() < 0x2000 || &b[0..8] != b"PAGEDU64" {
        return Ok(None);
    }
    let count = le32(b, 0x88) as u64;
    // A descriptor claiming more runs than could fit in the header is a
    // corrupted or differently-versioned dump; better to say so than to read
    // whatever follows as run descriptors.
    if count == 0 || count > 0x400 {
        return Err(MemoryError::Truncated(format!(
            "crash dump declares {count} physical memory runs, which is not plausible"
        )));
    }
    let mut runs = Vec::with_capacity(count as usize);
    let mut file = 0x2000u64;
    for i in 0..count {
        let at = 0x88 + 16 + (i as usize) * 16;
        if at + 16 > b.len() {
            return Err(MemoryError::Truncated("crash dump run list".into()));
        }
        let base_page = le64(b, at);
        let page_count = le64(b, at + 8);
        let len = page_count * PAGE;
        runs.push(Run { phys: base_page * PAGE, file, len });
        file += len;
    }
    Ok(Some(runs))
}

/// LiME, whose file is a sequence of `[header][payload]` pairs with no index.
fn lime(b: &[u8]) -> Option<Vec<Run>> {
    const MAGIC: u32 = 0x4C69_4D45; // "LiME" as stored little-endian.
    if b.len() < 32 || le32(b, 0) != MAGIC {
        return None;
    }
    let mut runs = Vec::new();
    let mut at = 0usize;
    while at + 32 <= b.len() && le32(b, at) == MAGIC {
        let start = le64(b, at + 8);
        let end = le64(b, at + 16);
        if end < start {
            break;
        }
        let len = end - start + 1;
        let file = (at + 32) as u64;
        if file + len > b.len() as u64 {
            // A truncated capture still has usable ranges before the cut.
            runs.push(Run { phys: start, file, len: b.len() as u64 - file });
            break;
        }
        runs.push(Run { phys: start, file, len });
        at = (file + len) as usize;
    }
    (!runs.is_empty()).then_some(runs)
}

/// ELF64 core, using `p_paddr` of each `PT_LOAD` as the physical base.
fn elf_core(b: &[u8]) -> Option<Vec<Run>> {
    if b.len() < 64 || &b[0..4] != b"\x7fELF" || b[4] != 2 || b[5] != 1 {
        return None;
    }
    let phoff = le64(b, 0x20) as usize;
    let phentsize = le16(b, 0x36) as usize;
    let phnum = le16(b, 0x38) as usize;
    if phentsize < 56 {
        return None;
    }
    let mut runs = Vec::new();
    for i in 0..phnum {
        let at = phoff + i * phentsize;
        if at + 56 > b.len() {
            break;
        }
        if le32(b, at) != 1 {
            continue; // not PT_LOAD
        }
        let offset = le64(b, at + 0x08);
        let paddr = le64(b, at + 0x18);
        let filesz = le64(b, at + 0x20);
        if filesz == 0 || offset + filesz > b.len() as u64 {
            continue;
        }
        runs.push(Run { phys: paddr, file: offset, len: filesz });
    }
    (!runs.is_empty()).then_some(runs)
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
