//! Chain of custody and collector self-accounting.
//!
//! Two things must be answerable from the case file alone, months later, without
//! the original host: *where did this byte come from* and *what did the tool
//! itself touch*. The first is [`ManifestEntry`], the second is [`Custody`].
//!
//! The self-accounting is not ceremony. The collector opens process handles,
//! reads raw volumes and writes files, which is indistinguishable from what an
//! implant does. Recording its own footprint is what lets an analyst subtract
//! the tool from the evidence instead of chasing it.

use serde::{Deserialize, Serialize};

use crate::time::Timestamp;

/// How a source artifact was obtained. This determines what side effects the
/// acquisition had, so it belongs in the manifest rather than in a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMethod {
    /// Read through the normal filesystem API. Updates last-access metadata and
    /// passes through filter drivers, so it is the method of last resort.
    Win32File,
    /// Read by parsing NTFS directly off a raw volume handle. Bypasses file
    /// locks and leaves `$STANDARD_INFORMATION` untouched.
    RawVolume,
    /// Read out of a Volume Shadow Copy, so the bytes predate the collection.
    VolumeShadowCopy,
    /// Live system API (process, network and service enumeration).
    LiveApi,
    /// Usermode process memory read.
    ProcessMemory,
    /// Physical memory via an external, separately provided driver.
    PhysicalMemoryDriver,
    /// Produced by the collector itself rather than read from the host.
    Derived,
}

impl AccessMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            AccessMethod::Win32File => "win32_file",
            AccessMethod::RawVolume => "raw_volume",
            AccessMethod::VolumeShadowCopy => "vss",
            AccessMethod::LiveApi => "live_api",
            AccessMethod::ProcessMemory => "process_memory",
            AccessMethod::PhysicalMemoryDriver => "physmem_driver",
            AccessMethod::Derived => "derived",
        }
    }

    pub fn from_str_lossy(s: &str) -> Option<Self> {
        Some(match s {
            "win32_file" => AccessMethod::Win32File,
            "raw_volume" => AccessMethod::RawVolume,
            "vss" => AccessMethod::VolumeShadowCopy,
            "live_api" => AccessMethod::LiveApi,
            "process_memory" => AccessMethod::ProcessMemory,
            "physmem_driver" => AccessMethod::PhysicalMemoryDriver,
            "derived" => AccessMethod::Derived,
            _ => return None,
        })
    }

    /// Whether this method perturbs the artifact it reads. Used by the viewer to
    /// warn when evidence was gathered by a method that altered the source.
    pub const fn perturbs_source(self) -> bool {
        matches!(self, AccessMethod::Win32File)
    }
}

/// One acquired source artifact, hashed and accounted for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Where it came from on the host, verbatim.
    pub source_path: String,
    pub method: AccessMethod,
    pub size_bytes: u64,
    /// SHA-256 of the acquired bytes, lowercase hex. `None` only when
    /// acquisition failed before any bytes were read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub started: Timestamp,
    pub finished: Timestamp,
    /// How many timeline events this artifact produced.
    pub events_emitted: u64,
    /// Populated when acquisition failed or was partial. A missing artifact is
    /// itself evidence, so failures are recorded rather than dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ManifestEntry {
    pub fn is_complete(&self) -> bool {
        self.error.is_none() && self.sha256.is_some()
    }
}

/// What the collector process itself was and did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Custody {
    pub collector_version: String,
    /// PID of the collector, so its own entries can be excluded from the tree.
    pub collector_pid: u32,
    pub collector_image: String,
    /// SHA-256 of the collector binary, so the tool that produced the case can
    /// be identified exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector_sha256: Option<String>,
    /// Command line as invoked, which records the flags that shaped the case.
    pub command_line: String,
    pub started: Timestamp,
    pub finished: Timestamp,
    /// Account the collector ran as.
    pub run_as_user: String,
    pub elevated: bool,
    /// Files the collector created on the host, if any. Ideally empty: the
    /// output should live on external media.
    #[serde(default)]
    pub files_written: Vec<String>,
    /// Non-fatal problems worth surfacing to the analyst.
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_win32_file_access_perturbs_the_source() {
        assert!(AccessMethod::Win32File.perturbs_source());
        assert!(!AccessMethod::RawVolume.perturbs_source());
        assert!(!AccessMethod::VolumeShadowCopy.perturbs_source());
    }

    #[test]
    fn access_methods_roundtrip() {
        for m in [
            AccessMethod::Win32File,
            AccessMethod::RawVolume,
            AccessMethod::VolumeShadowCopy,
            AccessMethod::LiveApi,
            AccessMethod::ProcessMemory,
            AccessMethod::PhysicalMemoryDriver,
            AccessMethod::Derived,
        ] {
            assert_eq!(AccessMethod::from_str_lossy(m.as_str()), Some(m));
        }
    }
}
