//! Native analysis of raw memory images.
//!
//! The Volatility framework established what this kind of analysis is made of:
//! an image is a set of physical page ranges; a page-table root turns those into
//! an address space; the kernel's own structures, read through that address
//! space, describe the machine. This crate implements those foundations
//! directly, in the collector's own language and process.
//!
//! The one place it deliberately differs is symbols. Volatility identifies the
//! kernel build and fetches matching debug symbols to learn where each structure
//! field sits. That is exact, and it is also a network dependency, a cache, and
//! a per-build profile. Here the field offsets are recovered from the image by
//! testing hypotheses against constraints the data itself has to satisfy — see
//! [`profile`] for how, and for the reasoning behind trusting it.
//!
//! What that buys, in practice: `tpv` reads a `.raw` on an air-gapped analysis
//! box, with no Python, no symbol server, and no profile for the specific
//! Windows build, and it works on builds released after this code was written.
//!
//! ```no_run
//! use tpv_memory::Analysis;
//!
//! let analysis = Analysis::open("memdump.raw")?;
//! for p in analysis.processes() {
//!     println!("{:>6}  {:<16} {}", p.pid, p.name, p.command_line.as_deref().unwrap_or(""));
//! }
//! # Ok::<(), tpv_memory::MemoryError>(())
//! ```

pub mod dtb;
pub mod error;
pub mod image;
pub mod linux;
pub mod paging;
pub mod process;
pub mod profile;
pub mod scan;

/// Image construction for tests.
///
/// Public behind a feature rather than private to the crate, so that downstream
/// crates can test their handling of memory-derived cases against an image whose
/// every value is known. A real capture cannot serve that purpose: it is too
/// large to commit, it contains whatever was in someone's RAM, and it would pin
/// the tests to one Windows build.
#[cfg(any(test, feature = "synthetic"))]
pub mod synthetic;

#[cfg(test)]
mod tests;

pub use error::{MemoryError, Result};
pub use image::{ImageFormat, PhysicalMemory, Run};
pub use paging::{AddressSpace, Residency};
pub use process::{Discovery, MemModule, MemProcess};
pub use profile::{EprocessLayout, KernelProfile};

use std::path::Path;

/// Which kernel the image appears to contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestOs {
    Windows,
    Linux,
}

/// An opened image, calibrated and enumerated.
///
/// The expensive work — scanning for page-table roots, calibrating the
/// structure layout, walking and scanning for processes — happens once, on
/// construction, because every part of it informs the next.
pub struct Analysis {
    memory: PhysicalMemory,
    os: GuestOs,
    profile: Option<KernelProfile>,
    linux_banner: Option<String>,
    processes: Vec<MemProcess>,
}

impl Analysis {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_memory(PhysicalMemory::open(path)?)
    }

    pub fn from_memory(memory: PhysicalMemory) -> Result<Self> {
        let banner = linux::kernel_banner(&memory);

        if memory.format() == ImageFormat::ElfCore {
            let notes = linux::from_elf_notes(memory.as_bytes());
            if !notes.is_empty() {
                return Ok(Self::linux(memory, banner, notes));
            }
        }

        if memory.format() == ImageFormat::Lime {
            let procs = linux::scan_tasks(&memory);
            return Ok(Self::linux(memory, banner, procs));
        }

        if memory.format() == ImageFormat::CrashDump64 {
            return Self::windows(memory, banner);
        }

        match Self::try_windows(&memory) {
            Ok((profile, processes))
                if !processes.is_empty() || profile.agreement >= 50 =>
            {
                Ok(Self {
                    memory,
                    os: GuestOs::Windows,
                    profile: Some(profile),
                    linux_banner: banner,
                    processes,
                })
            }
            Ok((profile, processes)) => {
                let linux_procs = linux::scan_tasks(&memory);
                if linux_procs.len() > processes.len() || banner.is_some() {
                    return Ok(Self::linux(memory, banner, linux_procs));
                }
                Ok(Self {
                    memory,
                    os: GuestOs::Windows,
                    profile: Some(profile),
                    linux_banner: banner,
                    processes,
                })
            }
            Err(win_err) => {
                let linux_procs = linux::scan_tasks(&memory);
                if !linux_procs.is_empty() || banner.is_some() {
                    return Ok(Self::linux(memory, banner, linux_procs));
                }
                Err(win_err)
            }
        }
    }

    fn windows(memory: PhysicalMemory, banner: Option<String>) -> Result<Self> {
        let (profile, processes) = Self::try_windows(&memory)?;
        Ok(Self {
            memory,
            os: GuestOs::Windows,
            profile: Some(profile),
            linux_banner: banner,
            processes,
        })
    }

    fn try_windows(memory: &PhysicalMemory) -> Result<(KernelProfile, Vec<MemProcess>)> {
        let roots = dtb::candidates_capped(memory, 4);
        if roots.is_empty() {
            return Err(MemoryError::NoDirectoryTableBase);
        }
        let profile = profile::calibrate(memory, &roots)?;
        let processes = process::enumerate(memory, &profile)?;
        Ok((profile, processes))
    }

    fn linux(memory: PhysicalMemory, banner: Option<String>, processes: Vec<MemProcess>) -> Self {
        Self {
            memory,
            os: GuestOs::Linux,
            profile: None,
            linux_banner: banner,
            processes,
        }
    }

    pub fn memory(&self) -> &PhysicalMemory {
        &self.memory
    }

    pub fn os(&self) -> GuestOs {
        self.os
    }

    pub fn profile(&self) -> Option<&KernelProfile> {
        self.profile.as_ref()
    }

    pub fn linux_banner(&self) -> Option<&str> {
        self.linux_banner.as_deref()
    }

    pub fn processes(&self) -> &[MemProcess] {
        &self.processes
    }

    /// Processes present in the pool but missing from the kernel's own list,
    /// which had not exited. This is the question the whole crate exists to
    /// answer cheaply.
    pub fn hidden(&self) -> impl Iterator<Item = &MemProcess> {
        self.processes.iter().filter(|p| p.hidden_from_list())
    }

    /// A process's address space, for reading its memory directly.
    pub fn address_space(&self, pid: u64) -> Option<AddressSpace<'_>> {
        let p = self.processes.iter().find(|p| p.pid == pid)?;
        if p.dtb == 0 {
            return None;
        }
        Some(AddressSpace::new(&self.memory, p.dtb))
    }
}
