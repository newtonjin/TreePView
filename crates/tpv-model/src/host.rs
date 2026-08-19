//! Host identity, reference clock, and what the collector was asked to do.

use serde::{Deserialize, Serialize};

use crate::time::Timestamp;

/// Identity of the machine the case was taken from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub architecture: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Machine GUID or equivalent, for correlating cases from the same host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone_name: Option<String>,
    /// Minutes to add to local time to reach UTC, as the host reported it at
    /// collection time. Every local-time artifact in the case was converted with
    /// this value, so it has to be preserved to make those conversions auditable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utc_offset_minutes: Option<i32>,
    /// System boot time, which bounds how far back live process evidence can go.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_time: Option<Timestamp>,
}

/// The reference clock captured at the very start of collection.
///
/// Taken first, before anything else, because every relative measurement in the
/// case is anchored to it and because a host clock that disagrees with reality
/// silently invalidates cross-host correlation. Recording it makes the skew
/// discoverable instead of mysterious.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReferenceClock {
    /// Host wall clock at collection start.
    pub host_utc: Timestamp,
    /// Milliseconds the host had been running, from a monotonic source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monotonic_uptime_ms: Option<u64>,
}

/// How much memory acquisition was performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryMode {
    /// Region metadata only. No process memory contents are read, so the
    /// footprint is minimal while still exposing unbacked executable regions.
    RegionsOnly,
    /// Minidump of processes selected by flag.
    SelectedProcesses,
    /// Minidump of every accessible process.
    AllProcesses,
    /// Full physical RAM through an external driver.
    PhysicalRam,
    /// The case was derived from a memory image acquired elsewhere, rather than
    /// from the host it describes. Distinct from `PhysicalRam` because nothing
    /// in such a case was observed live: absences reflect what the image
    /// captured, not what the machine had.
    ImageAnalysis,
    None,
}

impl MemoryMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            MemoryMode::RegionsOnly => "regions_only",
            MemoryMode::SelectedProcesses => "selected_processes",
            MemoryMode::AllProcesses => "all_processes",
            MemoryMode::PhysicalRam => "physical_ram",
            MemoryMode::ImageAnalysis => "image_analysis",
            MemoryMode::None => "none",
        }
    }

    pub fn from_str_lossy(s: &str) -> Option<Self> {
        Some(match s {
            "regions_only" => MemoryMode::RegionsOnly,
            "selected_processes" => MemoryMode::SelectedProcesses,
            "all_processes" => MemoryMode::AllProcesses,
            "physical_ram" => MemoryMode::PhysicalRam,
            "image_analysis" => MemoryMode::ImageAnalysis,
            "none" => MemoryMode::None,
            _ => return None,
        })
    }
}

/// What the collector was asked to gather.
///
/// Stored in the case so a reader can tell the difference between "this artifact
/// was absent" and "this artifact was never requested" — a distinction that
/// otherwise turns into a false negative.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CollectionProfile {
    pub memory: MemoryMode,
    /// PIDs explicitly requested, when `memory` is `SelectedProcesses`.
    #[serde(default)]
    pub selected_pids: Vec<u32>,
    pub live_state: bool,
    pub disk_artifacts: bool,
    /// High-value Windows event logs (Security, System, Application, and a
    /// small set of operational channels). Independent of `disk_artifacts`,
    /// which still gates MFT / Prefetch / hives.
    #[serde(default)]
    pub event_logs: bool,
    /// Per-channel cap on EVTX records. `None` means ingest the whole log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evtx_max_records: Option<u64>,
    /// Prefer Volume Shadow Copies over the live volume where available.
    pub prefer_vss: bool,
    /// Upper bound on collector resident memory, in mebibytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ram_mib: Option<u64>,
    /// Whether writing the case onto the volume under examination was permitted.
    pub allow_local_write: bool,
}

impl Default for CollectionProfile {
    fn default() -> Self {
        Self {
            memory: MemoryMode::RegionsOnly,
            selected_pids: Vec::new(),
            live_state: true,
            disk_artifacts: false,
            event_logs: false,
            evtx_max_records: None,
            prefer_vss: false,
            max_ram_mib: Some(512),
            allow_local_write: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_is_the_low_footprint_one() {
        let p = CollectionProfile::default();
        assert_eq!(p.memory, MemoryMode::RegionsOnly);
        assert!(p.live_state);
        assert!(!p.disk_artifacts);
        assert!(!p.event_logs);
        assert!(!p.allow_local_write);
    }

    #[test]
    fn memory_modes_roundtrip() {
        for m in [
            MemoryMode::RegionsOnly,
            MemoryMode::SelectedProcesses,
            MemoryMode::AllProcesses,
            MemoryMode::PhysicalRam,
            MemoryMode::None,
        ] {
            assert_eq!(MemoryMode::from_str_lossy(m.as_str()), Some(m));
        }
    }
}
