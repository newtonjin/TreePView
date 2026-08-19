//! Host identity and the reference clock.
//!
//! Collected first, before anything else, because every other measurement in the
//! case is interpreted against it. In particular the time-zone bias recorded
//! here is what every local-time artifact later in the collection is converted
//! with, so it has to be captured from the same machine state those artifacts
//! were read under.

#![allow(unsafe_code)]

use windows::core::PCWSTR;
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    KEY_WOW64_64KEY, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
};
use windows::Win32::System::SystemInformation::{
    GetComputerNameExW, GetNativeSystemInfo, GetSystemTimePreciseAsFileTime, GetTickCount64,
    ComputerNameDnsDomain, ComputerNamePhysicalDnsHostname, SYSTEM_INFO,
};
use windows::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};

use crate::sys::{filetime_to_i64, to_wide, wide_to_string};

/// Everything about the machine that shapes how its artifacts are read.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LiveHostInfo {
    pub hostname: String,
    pub domain: Option<String>,
    pub os_name: String,
    pub os_version: String,
    pub architecture: String,
    pub machine_id: Option<String>,
    pub timezone_name: Option<String>,
    /// Minutes to add to local time to reach UTC.
    pub utc_offset_minutes: Option<i32>,
    /// Host wall clock at capture, as a raw `FILETIME`.
    pub now_filetime: i64,
    /// Boot time derived from the monotonic uptime counter, as a `FILETIME`.
    pub boot_time_filetime: Option<i64>,
    pub uptime_ms: u64,
}

fn computer_name(kind: windows::Win32::System::SystemInformation::COMPUTER_NAME_FORMAT) -> Option<String> {
    let mut len = 0u32;
    unsafe {
        let _ = GetComputerNameExW(kind, None, &mut len);
    }
    if len == 0 {
        return None;
    }
    let mut buf = vec![0u16; len as usize + 1];
    let mut cap = buf.len() as u32;
    unsafe {
        GetComputerNameExW(kind, Some(windows::core::PWSTR(buf.as_mut_ptr())), &mut cap).ok()?;
    }
    let s = wide_to_string(&buf);
    (!s.is_empty()).then_some(s)
}

/// Read one string value from a registry key under HKLM.
fn hklm_string(subkey: &str, value: &str) -> Option<String> {
    let sub = to_wide(subkey);
    let val = to_wide(value);
    let mut key = HKEY::default();

    if unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(sub.as_ptr()),
            None,
            KEY_READ | KEY_WOW64_64KEY,
            &mut key,
        )
    }
    .is_err()
    {
        return None;
    }

    let mut kind = REG_VALUE_TYPE::default();
    let mut data = [0u8; 4096];
    let mut len = data.len() as u32;
    let rc = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(val.as_ptr()),
            None,
            Some(&mut kind),
            Some(data.as_mut_ptr()),
            Some(&mut len),
        )
    };
    unsafe {
        let _ = RegCloseKey(key);
    }

    if rc.is_err() || (kind != REG_SZ && kind != REG_EXPAND_SZ) {
        return None;
    }
    let chars = (len as usize) / 2;
    let units: Vec<u16> = data[..chars * 2]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let s = wide_to_string(&units);
    (!s.is_empty()).then_some(s)
}

fn architecture() -> String {
    let mut info = SYSTEM_INFO::default();
    unsafe { GetNativeSystemInfo(&mut info) };
    // Reading the *native* architecture matters: a 32-bit collector on a 64-bit
    // host would otherwise report x86 and mislead every later interpretation.
    match unsafe { info.Anonymous.Anonymous.wProcessorArchitecture.0 } {
        0 => "x86".into(),
        5 => "arm".into(),
        9 => "x86_64".into(),
        12 => "arm64".into(),
        other => format!("unknown({other})"),
    }
}

/// Capture host identity and the reference clock.
pub fn capture() -> LiveHostInfo {
    let now = filetime_to_i64(unsafe { GetSystemTimePreciseAsFileTime() });
    let uptime_ms = unsafe { GetTickCount64() };

    // The boot time is not stored anywhere directly, so it is derived from the
    // monotonic uptime. That derivation is only as good as the current clock,
    // which is exactly why both are recorded rather than just the result.
    let boot_time_filetime = {
        const TICKS_PER_MS: i64 = 10_000;
        now.checked_sub(uptime_ms as i64 * TICKS_PER_MS)
    };

    let mut tz = TIME_ZONE_INFORMATION::default();
    let tz_result = unsafe { GetTimeZoneInformation(&mut tz) };
    // TIME_ZONE_ID_INVALID is 0xFFFFFFFF; anything else means the fields are
    // populated. Daylight saving shifts the effective bias, so the active bias
    // is what gets recorded rather than the standard one.
    let (timezone_name, utc_offset_minutes) = if tz_result == u32::MAX {
        (None, None)
    } else {
        let extra = match tz_result {
            2 => tz.DaylightBias,
            1 => tz.StandardBias,
            _ => 0,
        };
        let name = if tz_result == 2 {
            wide_to_string(&tz.DaylightName)
        } else {
            wide_to_string(&tz.StandardName)
        };
        (
            (!name.is_empty()).then_some(name),
            Some(tz.Bias + extra),
        )
    };

    let product = hklm_string(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName");
    let build = hklm_string(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild");
    let ubr = hklm_string(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion");

    LiveHostInfo {
        hostname: computer_name(ComputerNamePhysicalDnsHostname).unwrap_or_else(|| "unknown".into()),
        domain: computer_name(ComputerNameDnsDomain).filter(|s| !s.is_empty()),
        os_name: product.unwrap_or_else(|| "Windows".into()),
        os_version: match (build, ubr) {
            (Some(b), Some(d)) => format!("{d} (build {b})"),
            (Some(b), None) => format!("build {b}"),
            _ => "unknown".into(),
        },
        architecture: architecture(),
        machine_id: hklm_string(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid"),
        timezone_name,
        utc_offset_minutes,
        now_filetime: now,
        boot_time_filetime,
        uptime_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpv_model::Timestamp;

    #[test]
    fn captures_a_coherent_host_identity() {
        let h = capture();
        assert_ne!(h.hostname, "unknown");
        assert!(!h.os_name.is_empty());
        assert_eq!(h.architecture, "x86_64", "this project targets x64 hosts");
        assert!(h.machine_id.is_some(), "MachineGuid is readable by any user");
        assert!(h.uptime_ms > 0);
    }

    #[test]
    fn reference_clock_is_plausible_and_boot_precedes_now() {
        let h = capture();
        let now = Timestamp::from_filetime(h.now_filetime);
        assert!(!now.is_suspect(), "the host clock must land in a sane range");

        // Sanity floor: 2020-01-01. A clock behind this means the host time is
        // wrong, which is a finding rather than a collection bug, but it would
        // also mean this test is not measuring what it thinks it is.
        assert!(now.utc_ns > 1_577_836_800_000_000_000);

        let boot = h.boot_time_filetime.expect("uptime is always available");
        assert!(boot < h.now_filetime, "boot time must precede the capture");
    }

    #[test]
    fn timezone_bias_is_recorded() {
        let h = capture();
        let bias = h
            .utc_offset_minutes
            .expect("a configured Windows host always reports a bias");
        // Real offsets span UTC-12 to UTC+14, expressed as a bias in minutes.
        assert!((-14 * 60..=12 * 60).contains(&bias), "implausible bias {bias}");
    }
}
