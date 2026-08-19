//! What the collector is, from the inside.
//!
//! The collector opens process handles, reads memory and walks raw volumes,
//! which is behaviourally identical to an implant. Recording its own identity is
//! what lets an analyst subtract the tool from the evidence instead of
//! investigating it.

#![allow(unsafe_code)]

use windows::Win32::Foundation::{HANDLE, MAX_PATH};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, OpenProcessToken,
};

use crate::sys::{wide_ptr_to_string, wide_to_string, OwnedHandle};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SelfInfo {
    pub pid: u32,
    pub image: String,
    pub command_line: String,
    pub elevated: bool,
}

/// Describe the running collector process.
pub fn capture() -> SelfInfo {
    let mut buf = [0u16; MAX_PATH as usize * 2];
    let n = unsafe { GetModuleFileNameW(None, &mut buf) };
    let image = if n > 0 {
        wide_to_string(&buf[..n as usize])
    } else {
        String::new()
    };

    let command_line = unsafe {
        let p = windows::Win32::System::Environment::GetCommandLineW();
        wide_ptr_to_string(p.0, 32 * 1024)
    };

    SelfInfo {
        pid: unsafe { GetCurrentProcessId() },
        image,
        command_line,
        elevated: is_elevated(),
    }
}

/// Whether the collector holds an elevated token.
///
/// Not cosmetic: without elevation the raw volume, VSS and registry hives are
/// simply unavailable, and a case collected unelevated is missing whole
/// artifact classes. The analyst has to be able to tell that apart from those
/// artifacts being genuinely absent.
pub fn is_elevated() -> bool {
    let mut token = HANDLE::default();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return false;
    }
    let token = unsafe { OwnedHandle::new(token) };

    let mut elevation = TOKEN_ELEVATION::default();
    let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
    let ok = unsafe {
        GetTokenInformation(
            token.raw(),
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            size,
            &mut size,
        )
    }
    .is_ok();

    ok && elevation.TokenIsElevated != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_the_running_process() {
        let me = capture();
        assert_eq!(me.pid, std::process::id());
        assert!(
            me.image.to_ascii_lowercase().ends_with(".exe"),
            "unexpected image path {}",
            me.image
        );
        assert!(!me.command_line.is_empty());
    }
}
