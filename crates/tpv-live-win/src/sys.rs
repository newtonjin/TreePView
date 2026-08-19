//! Thin helpers over the Win32 surface.
//!
//! Two recurring concerns are handled here so the collection modules can stay
//! readable: converting the UTF-16 buffers Windows hands back into Rust strings,
//! and making sure every handle the collector opens is closed. The second one is
//! not hygiene for its own sake — a triage tool that leaks handles into a
//! compromised process changes the very state an analyst is about to measure.

#![allow(unsafe_code)]

use windows::Win32::Foundation::{CloseHandle, HANDLE};

/// Owns a Win32 handle and closes it on drop.
///
/// The collector opens hundreds of process handles in a single run. Closing them
/// by hand at every early return is exactly the kind of bookkeeping that goes
/// wrong under `?`, so ownership is made explicit instead.
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    /// # Safety
    /// The handle must be valid and not owned by anything else.
    pub unsafe fn new(h: HANDLE) -> Self {
        Self(h)
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // Nothing useful can be done if this fails, and failing to close is
            // not a reason to abort a collection already in progress.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Decode a UTF-16 buffer, stopping at the first NUL.
///
/// Lossy on purpose. Paths and command lines on a compromised host are attacker
/// controlled and are not required to be well-formed UTF-16; refusing to decode
/// them would drop exactly the evidence worth looking at.
pub fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Decode a NUL-terminated UTF-16 string from a raw pointer.
///
/// # Safety
/// `ptr` must point to a NUL-terminated UTF-16 string of at most `max_chars`.
pub unsafe fn wide_ptr_to_string(ptr: *const u16, max_chars: usize) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while len < max_chars && unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}

/// Convert a Rust string into a NUL-terminated UTF-16 buffer.
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Join the high and low halves of a `FILETIME` into the i64 the model expects.
pub fn filetime_to_i64(ft: windows::Win32::Foundation::FILETIME) -> i64 {
    (((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_decoding_stops_at_nul() {
        let buf: Vec<u16> = "cmd.exe\0garbage".encode_utf16().collect();
        assert_eq!(wide_to_string(&buf), "cmd.exe");
    }

    #[test]
    fn wide_decoding_handles_an_unterminated_buffer() {
        let buf: Vec<u16> = "svchost.exe".encode_utf16().collect();
        assert_eq!(wide_to_string(&buf), "svchost.exe");
    }

    #[test]
    fn lone_surrogates_do_not_lose_the_rest_of_the_string() {
        // A path an attacker can produce that is not valid UTF-16.
        let buf: Vec<u16> = vec![0x0041, 0xD800, 0x0042, 0x0000];
        let s = wide_to_string(&buf);
        assert!(s.starts_with('A'));
        assert!(s.ends_with('B'));
    }

    #[test]
    fn filetime_halves_recombine() {
        let ft = windows::Win32::Foundation::FILETIME {
            dwLowDateTime: 0x9ABC_DEF0,
            dwHighDateTime: 0x1234_5678,
        };
        assert_eq!(filetime_to_i64(ft), 0x1234_5678_9ABC_DEF0);
    }
}
