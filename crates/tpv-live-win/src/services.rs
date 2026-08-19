//! Service and kernel driver acquisition.
//!
//! Services are where persistence lives, so both the running state and the
//! configured binary path are collected. The two disagree more often than one
//! would like — a service can be configured to run a binary that no longer
//! exists, or point at a path with an unquoted space — and that disagreement is
//! precisely what an analyst is looking for.

#![allow(unsafe_code)]

use windows::core::PCWSTR;
use windows::Win32::Foundation::MAX_PATH;
use windows::Win32::System::ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverFileNameW};
use windows::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
    ENUM_SERVICE_STATUS_PROCESSW, QUERY_SERVICE_CONFIGW, SC_ENUM_PROCESS_INFO,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_DRIVER, SERVICE_QUERY_CONFIG, SERVICE_STATE_ALL,
    SERVICE_WIN32,
};

use crate::sys::{to_wide, wide_ptr_to_string, wide_to_string};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServiceRecord {
    pub name: String,
    pub display_name: String,
    pub state: String,
    /// PID when running, absent otherwise.
    pub pid: Option<u32>,
    pub service_type: String,
    pub start_type: Option<String>,
    /// Configured command line, which may differ from what is actually running.
    pub binary_path: Option<String>,
    pub account: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DriverRecord {
    pub name: String,
    pub path: Option<String>,
    pub base: u64,
}

fn service_state(state: u32) -> &'static str {
    match state {
        1 => "stopped",
        2 => "start_pending",
        3 => "stop_pending",
        4 => "running",
        5 => "continue_pending",
        6 => "pause_pending",
        7 => "paused",
        _ => "unknown",
    }
}

fn start_type(t: u32) -> &'static str {
    match t {
        0 => "boot",
        1 => "system",
        2 => "auto",
        3 => "demand",
        4 => "disabled",
        _ => "unknown",
    }
}

fn service_type(t: u32) -> String {
    let mut parts = Vec::new();
    if t & 0x1 != 0 {
        parts.push("kernel_driver");
    }
    if t & 0x2 != 0 {
        parts.push("fs_driver");
    }
    if t & 0x10 != 0 {
        parts.push("own_process");
    }
    if t & 0x20 != 0 {
        parts.push("share_process");
    }
    if t & 0x100 != 0 {
        parts.push("interactive");
    }
    if parts.is_empty() {
        format!("0x{t:x}")
    } else {
        parts.join("|")
    }
}

/// Enumerate every service, running or not.
///
/// Stopped services are included deliberately: a disabled or stopped service
/// pointing at a dropped binary is a common persistence pattern, and collecting
/// only what is running would miss it entirely.
pub fn enumerate_services() -> Result<Vec<ServiceRecord>, String> {
    let scm = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) }
        .map_err(|e| format!("OpenSCManager failed: {e}"))?;

    let result = enumerate_with_scm(scm);
    unsafe {
        let _ = CloseServiceHandle(scm);
    }
    result
}

fn enumerate_with_scm(
    scm: windows::Win32::System::Services::SC_HANDLE,
) -> Result<Vec<ServiceRecord>, String> {
    let mut needed = 0u32;
    let mut returned = 0u32;
    let mut resume = 0u32;

    // Sizing call. It is expected to fail; the useful output is `needed`.
    unsafe {
        let _ = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32 | SERVICE_DRIVER,
            SERVICE_STATE_ALL,
            None,
            &mut needed,
            &mut returned,
            Some(&mut resume),
            PCWSTR::null(),
        );
    }
    if needed == 0 {
        return Ok(Vec::new());
    }

    let mut buf = vec![0u8; needed as usize];
    unsafe {
        EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32 | SERVICE_DRIVER,
            SERVICE_STATE_ALL,
            Some(&mut buf),
            &mut needed,
            &mut returned,
            Some(&mut resume),
            PCWSTR::null(),
        )
    }
    .map_err(|e| format!("EnumServicesStatusEx failed: {e}"))?;

    let entries = unsafe {
        std::slice::from_raw_parts(
            buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
            returned as usize,
        )
    };

    Ok(entries
        .iter()
        .map(|e| {
            let name = unsafe { wide_ptr_to_string(e.lpServiceName.0, 1024) };
            let status = e.ServiceStatusProcess;
            let mut rec = ServiceRecord {
                display_name: unsafe { wide_ptr_to_string(e.lpDisplayName.0, 1024) },
                state: service_state(status.dwCurrentState.0).into(),
                pid: (status.dwProcessId != 0).then_some(status.dwProcessId),
                service_type: service_type(status.dwServiceType.0),
                start_type: None,
                binary_path: None,
                account: None,
                name,
            };
            // Configuration is a separate, per-service call. It can be denied
            // without elevation, in which case the running state is still worth
            // keeping.
            if let Some((path, start, account)) = query_config(scm, &rec.name) {
                rec.binary_path = Some(path);
                rec.start_type = Some(start);
                rec.account = account;
            }
            rec
        })
        .collect())
}

fn query_config(
    scm: windows::Win32::System::Services::SC_HANDLE,
    name: &str,
) -> Option<(String, String, Option<String>)> {
    let wide = to_wide(name);
    let svc = unsafe { OpenServiceW(scm, PCWSTR(wide.as_ptr()), SERVICE_QUERY_CONFIG) }.ok()?;

    let mut needed = 0u32;
    unsafe {
        let _ = QueryServiceConfigW(svc, None, 0, &mut needed);
    }

    let result = if needed > 0 && (needed as usize) < (1 << 20) {
        let mut buf = vec![0u8; needed as usize];
        let cfg = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
        if unsafe { QueryServiceConfigW(svc, Some(cfg), needed, &mut needed) }.is_ok() {
            let cfg = unsafe { &*cfg };
            Some((
                unsafe { wide_ptr_to_string(cfg.lpBinaryPathName.0, 4096) },
                start_type(cfg.dwStartType.0).to_string(),
                Some(unsafe { wide_ptr_to_string(cfg.lpServiceStartName.0, 1024) })
                    .filter(|s| !s.is_empty()),
            ))
        } else {
            None
        }
    } else {
        None
    };

    unsafe {
        let _ = CloseServiceHandle(svc);
    }
    result
}

/// Enumerate loaded kernel modules.
///
/// Without elevation Windows reports the base addresses as zero, which is not a
/// failure so much as a redaction. The names are still returned and still worth
/// having, so the redaction is passed through rather than treated as an error.
pub fn enumerate_drivers() -> Result<Vec<DriverRecord>, String> {
    let mut needed = 0u32;
    unsafe { EnumDeviceDrivers(std::ptr::null_mut(), 0, &mut needed) }
        .map_err(|e| format!("EnumDeviceDrivers sizing failed: {e}"))?;
    if needed == 0 {
        return Ok(Vec::new());
    }

    let count = needed as usize / std::mem::size_of::<*mut std::ffi::c_void>();
    let mut bases: Vec<*mut std::ffi::c_void> = vec![std::ptr::null_mut(); count];
    unsafe { EnumDeviceDrivers(bases.as_mut_ptr(), needed, &mut needed) }
        .map_err(|e| format!("EnumDeviceDrivers failed: {e}"))?;

    let actual = (needed as usize / std::mem::size_of::<*mut std::ffi::c_void>()).min(bases.len());

    Ok(bases
        .iter()
        .take(actual)
        .map(|base| {
            let mut buf = [0u16; MAX_PATH as usize * 2];
            let n = unsafe { GetDeviceDriverFileNameW(*base, &mut buf) };
            let path = (n > 0).then(|| wide_to_string(&buf[..n as usize]));
            let name = path
                .as_deref()
                .and_then(|p| p.rsplit('\\').next())
                .unwrap_or("<unknown>")
                .to_string();
            DriverRecord {
                name,
                path,
                base: *base as u64,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_states_and_start_types_decode() {
        assert_eq!(service_state(4), "running");
        assert_eq!(service_state(1), "stopped");
        assert_eq!(start_type(2), "auto");
        assert_eq!(start_type(4), "disabled");
    }

    #[test]
    fn service_type_flags_decompose() {
        assert_eq!(service_type(0x10), "own_process");
        assert_eq!(service_type(0x1), "kernel_driver");
        assert_eq!(service_type(0x30), "own_process|share_process");
        assert_eq!(service_type(0x800), "0x800");
    }

    #[test]
    fn enumerates_live_services_including_stopped_ones() {
        let services = enumerate_services().expect("SCM enumeration must work unelevated");
        assert!(services.len() > 20, "Windows ships with many services");

        // The event log service exists on every Windows install and is running.
        let eventlog = services
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case("EventLog"))
            .expect("EventLog service must be present");
        assert_eq!(eventlog.state, "running");
        assert!(eventlog.pid.is_some());

        assert!(
            services.iter().any(|s| s.state == "stopped"),
            "stopped services must be collected, not filtered out"
        );
        assert!(
            services.iter().any(|s| s.binary_path.is_some()),
            "service configuration should be readable for at least some services"
        );
    }

    #[test]
    fn enumerates_loaded_drivers() {
        let drivers = enumerate_drivers().expect("driver enumeration must not fail outright");
        assert!(!drivers.is_empty(), "the kernel always has modules loaded");
        assert!(
            drivers
                .iter()
                .any(|d| d.name.eq_ignore_ascii_case("ntoskrnl.exe")),
            "the kernel image itself must appear"
        );
    }
}
