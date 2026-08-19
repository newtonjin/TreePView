//! Volatile Windows state acquisition.
//!
//! This crate only *reads*. It knows nothing about the `.tpv` container or about
//! timelines: it returns plain structs, and [`tpv_collect`](../tpv_collect) turns
//! them into events. Keeping the boundary there means the Windows-specific unsafe
//! code has one job, and the Linux collector in M7 can slot in beside it without
//! either knowing about the other.
//!
//! Ordering follows volatility. The reference clock is captured first because
//! everything else is interpreted against it, then network state (which changes
//! by the second), then processes, then the comparatively stable service,
//! driver and autostart configuration.

#![cfg(windows)]

pub mod autoruns;
pub mod hostinfo;
pub mod net;
pub mod process;
pub mod selfinfo;
pub mod services;
pub mod sys;

pub use autoruns::AutorunRecord;
pub use hostinfo::LiveHostInfo;
pub use net::NetEndpoint;
pub use process::{LiveModule, LiveProcess, ProcessOptions};
pub use selfinfo::SelfInfo;
pub use services::{DriverRecord, ServiceRecord};

/// What to collect from the live system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveOptions {
    pub processes: ProcessOptions,
    pub network: bool,
    pub services: bool,
    pub drivers: bool,
    pub autoruns: bool,
}

impl Default for LiveOptions {
    fn default() -> Self {
        Self {
            processes: ProcessOptions::default(),
            network: true,
            services: true,
            drivers: true,
            autoruns: true,
        }
    }
}

/// Everything read from the live system in one pass.
#[derive(Debug, Clone, Default)]
pub struct LiveSnapshot {
    pub host: Option<LiveHostInfo>,
    pub processes: Vec<LiveProcess>,
    pub endpoints: Vec<NetEndpoint>,
    pub services: Vec<ServiceRecord>,
    pub drivers: Vec<DriverRecord>,
    pub autoruns: Vec<AutorunRecord>,
    /// Everything that went wrong without stopping the collection. A triage run
    /// on a host where half the processes were unreadable is still useful, but
    /// only if the analyst is told which half.
    pub warnings: Vec<String>,
}

/// Read the live system.
///
/// Never returns an error: a partial snapshot with recorded warnings is
/// categorically more useful during an incident than a clean failure.
pub fn collect(opts: LiveOptions) -> LiveSnapshot {
    let mut snap = LiveSnapshot {
        host: Some(hostinfo::capture()),
        ..Default::default()
    };

    // Sockets first among the enumerations: connection tables turn over faster
    // than anything else here, so the gap between the reference clock and this
    // read is the one worth minimizing.
    if opts.network {
        let (endpoints, warnings) = net::enumerate();
        snap.endpoints = endpoints;
        snap.warnings.extend(warnings);
    }

    match process::enumerate(opts.processes) {
        Ok(procs) => snap.processes = procs,
        Err(e) => snap.warnings.push(format!("process enumeration: {e}")),
    }

    if opts.services {
        match services::enumerate_services() {
            Ok(s) => snap.services = s,
            Err(e) => snap.warnings.push(format!("service enumeration: {e}")),
        }
    }

    if opts.drivers {
        match services::enumerate_drivers() {
            Ok(d) => snap.drivers = d,
            Err(e) => snap.warnings.push(format!("driver enumeration: {e}")),
        }
    }

    if opts.autoruns {
        let (entries, warnings) = autoruns::enumerate();
        snap.autoruns = entries;
        snap.warnings.extend(warnings);
    }

    snap
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_snapshot_is_internally_consistent() {
        let snap = collect(LiveOptions::default());

        assert!(snap.host.is_some());
        assert!(!snap.processes.is_empty());
        assert!(!snap.endpoints.is_empty());
        assert!(!snap.services.is_empty());

        // Every socket must be attributable to a process in the same snapshot,
        // or else the tree cannot explain the network activity. PID 0 is the
        // kernel's placeholder for sockets with no usermode owner.
        let pids: std::collections::HashSet<u32> = snap.processes.iter().map(|p| p.pid).collect();
        let orphans = snap
            .endpoints
            .iter()
            .filter(|e| e.pid != 0 && !pids.contains(&e.pid))
            .count();
        // A few are expected: processes exit between the two enumerations.
        assert!(
            orphans < snap.endpoints.len() / 4,
            "{orphans} of {} sockets could not be attributed",
            snap.endpoints.len()
        );

        // Running services must point at live processes for the same reason.
        let unattributed = snap
            .services
            .iter()
            .filter_map(|s| s.pid)
            .filter(|pid| !pids.contains(pid))
            .count();
        assert!(unattributed <= 2, "{unattributed} running services have no process");
    }

    #[test]
    fn options_actually_suppress_work() {
        let snap = collect(LiveOptions {
            processes: ProcessOptions {
                command_lines: false,
                modules: false,
                tokens: false,
            },
            network: false,
            services: false,
            drivers: false,
            autoruns: false,
        });

        assert!(snap.endpoints.is_empty());
        assert!(snap.services.is_empty());
        assert!(snap.drivers.is_empty());
        assert!(snap.autoruns.is_empty());
        assert!(!snap.processes.is_empty(), "processes are always collected");
        assert!(snap.processes.iter().all(|p| p.modules.is_empty()));
        assert!(snap.processes.iter().all(|p| p.command_line.is_none()));
    }
}
