//! Process, module and token acquisition.
//!
//! The enumeration is deliberately layered by cost. A single toolhelp snapshot
//! yields every PID, parent PID and thread count without opening anything. Only
//! then does the collector open individual processes, and only with the least
//! privilege that answers the question: `PROCESS_QUERY_LIMITED_INFORMATION` is
//! enough for creation time, image path and command line, and works without
//! elevation against most processes.
//!
//! Module enumeration is the one step that needs `PROCESS_VM_READ`, so it is
//! separately switchable. On a host being triaged, the difference between
//! opening every process for read and merely asking its name is a real
//! difference in footprint, and the operator should get to choose.

#![allow(unsafe_code)]

use std::collections::HashMap;

use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
use windows::Win32::Foundation::{FILETIME, HANDLE, MAX_PATH, UNICODE_STRING};
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, TokenElevation, TokenUser, SID_NAME_USE,
    TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    GetProcessHandleCount, GetProcessTimes, IsWow64Process, OpenProcess, OpenProcessToken,
    QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ,
};

use crate::sys::{filetime_to_i64, wide_ptr_to_string, wide_to_string, OwnedHandle};

/// `ProcessCommandLineInformation`. Not in the public headers, but stable since
/// Windows 8.1 and the only way to read another process's command line without
/// walking its PEB through `ReadProcessMemory` — which would require opening the
/// process for VM read and would fail across the 32/64-bit boundary.
const PROCESS_COMMAND_LINE_INFORMATION: PROCESSINFOCLASS = PROCESSINFOCLASS(60);

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LiveModule {
    pub name: String,
    pub path: Option<String>,
    pub base: u64,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct LiveProcess {
    pub pid: u32,
    pub ppid: Option<u32>,
    /// Image base name as reported by the snapshot. Always present, even when
    /// the process could not be opened.
    pub name: String,
    pub image_path: Option<String>,
    pub command_line: Option<String>,
    /// Raw `FILETIME`. Converted by the caller so this crate stays free of
    /// timeline concerns.
    pub create_time_filetime: Option<i64>,
    pub user: Option<String>,
    pub user_sid: Option<String>,
    pub session_id: Option<u32>,
    pub thread_count: u32,
    pub handle_count: Option<u32>,
    pub is_wow64: Option<bool>,
    pub elevated: Option<bool>,
    pub modules: Vec<LiveModule>,
    /// Why the process could not be fully inspected. Protected processes and
    /// processes owned by other users routinely land here without elevation, and
    /// that fact is itself worth recording: a triage where `lsass.exe` could not
    /// be opened is a different triage from one where it was inspected clean.
    pub access_error: Option<String>,
}

/// What to spend footprint on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessOptions {
    /// Read each process's command line. One extra query per process, no VM read.
    pub command_lines: bool,
    /// Enumerate loaded modules. Requires opening each process for VM read,
    /// which is the heaviest thing the live collector does.
    pub modules: bool,
    /// Resolve the owning user via the process token.
    pub tokens: bool,
}

impl Default for ProcessOptions {
    fn default() -> Self {
        Self {
            command_lines: true,
            modules: true,
            tokens: true,
        }
    }
}

/// Snapshot every process on the system.
///
/// Never fails as a whole for a single inaccessible process: the failure is
/// recorded on that process and enumeration continues, because a collector that
/// aborts on the first protected process is useless on a real host.
pub fn enumerate(opts: ProcessOptions) -> Result<Vec<LiveProcess>, String> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| format!("CreateToolhelp32Snapshot failed: {e}"))?;
    let snapshot = unsafe { OwnedHandle::new(snapshot) };

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut out = Vec::with_capacity(512);
    if unsafe { Process32FirstW(snapshot.raw(), &mut entry) }.is_err() {
        return Err("Process32FirstW returned no processes".into());
    }

    loop {
        out.push(LiveProcess {
            pid: entry.th32ProcessID,
            // PID 0 is not a real parent; the idle process is its own ancestor
            // and treating it as a parent produces a self-referential tree.
            ppid: match entry.th32ParentProcessID {
                0 => None,
                p if p == entry.th32ProcessID => None,
                p => Some(p),
            },
            name: wide_to_string(&entry.szExeFile),
            thread_count: entry.cntThreads,
            ..Default::default()
        });

        if unsafe { Process32NextW(snapshot.raw(), &mut entry) }.is_err() {
            break;
        }
    }

    for p in &mut out {
        enrich(p, opts);
    }
    Ok(out)
}

/// Fill in everything that requires opening the process.
fn enrich(p: &mut LiveProcess, opts: ProcessOptions) {
    // The idle and system processes cannot be opened and have no meaningful
    // image, so skipping them avoids two guaranteed access-denied entries that
    // would otherwise look like collection failures.
    if p.pid == 0 {
        p.name = "System Idle Process".into();
        return;
    }

    let mut session = 0u32;
    if unsafe { ProcessIdToSessionId(p.pid, &mut session) }.is_ok() {
        p.session_id = Some(session);
    }

    let mut desired = PROCESS_QUERY_LIMITED_INFORMATION;
    if opts.modules {
        desired |= PROCESS_VM_READ;
    }

    let handle = match unsafe { OpenProcess(desired, false, p.pid) } {
        Ok(h) => unsafe { OwnedHandle::new(h) },
        Err(e) => {
            // Retry without VM read: many processes allow the cheap queries but
            // not memory access, and losing their metadata over a module list we
            // could not have read anyway would be a poor trade.
            match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, p.pid) } {
                Ok(h) => {
                    p.access_error = Some(format!("modules unavailable: {e}"));
                    unsafe { OwnedHandle::new(h) }
                }
                Err(e) => {
                    p.access_error = Some(format!("OpenProcess failed: {e}"));
                    return;
                }
            }
        }
    };
    let h = handle.raw();

    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe { GetProcessTimes(h, &mut created, &mut exited, &mut kernel, &mut user) }.is_ok() {
        p.create_time_filetime = Some(filetime_to_i64(created));
    }

    let mut buf = [0u16; MAX_PATH as usize * 2];
    let mut len = buf.len() as u32;
    if unsafe {
        QueryFullProcessImageNameW(
            h,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    }
    .is_ok()
    {
        p.image_path = Some(wide_to_string(&buf[..len as usize]));
    }

    let mut handles = 0u32;
    if unsafe { GetProcessHandleCount(h, &mut handles) }.is_ok() {
        p.handle_count = Some(handles);
    }

    let mut wow64 = windows::core::BOOL(0);
    if unsafe { IsWow64Process(h, &mut wow64) }.is_ok() {
        p.is_wow64 = Some(wow64.as_bool());
    }

    if opts.command_lines {
        p.command_line = unsafe { query_command_line(h) };
    }
    if opts.tokens {
        unsafe { query_token(h, p) };
    }
    if opts.modules {
        p.modules = unsafe { enumerate_modules(h) };
    }
}

/// Read a process's command line through `NtQueryInformationProcess`.
unsafe fn query_command_line(h: HANDLE) -> Option<String> {
    // Ask for the size first. The call is expected to fail with
    // STATUS_INFO_LENGTH_MISMATCH while still reporting the length it needs.
    let mut needed = 0u32;
    unsafe {
        let _ = NtQueryInformationProcess(
            h,
            PROCESS_COMMAND_LINE_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 || needed as usize > 1 << 20 {
        return None;
    }

    let mut buf = vec![0u8; needed as usize];
    let status = unsafe {
        NtQueryInformationProcess(
            h,
            PROCESS_COMMAND_LINE_INFORMATION,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if status.is_err() {
        return None;
    }

    // The buffer is a UNICODE_STRING whose payload follows the header.
    if buf.len() < std::mem::size_of::<UNICODE_STRING>() {
        return None;
    }
    let us = unsafe { &*(buf.as_ptr() as *const UNICODE_STRING) };
    if us.Buffer.is_null() || us.Length == 0 {
        return None;
    }
    let s = unsafe { wide_ptr_to_string(us.Buffer.0, (us.Length / 2) as usize) };
    (!s.is_empty()).then_some(s)
}

/// Resolve the owning account and elevation state from the process token.
unsafe fn query_token(h: HANDLE, p: &mut LiveProcess) {
    let mut token = HANDLE::default();
    if unsafe { OpenProcessToken(h, TOKEN_QUERY, &mut token) }.is_err() {
        return;
    }
    let token = unsafe { OwnedHandle::new(token) };

    let mut needed = 0u32;
    unsafe {
        let _ = GetTokenInformation(token.raw(), TokenUser, None, 0, &mut needed);
    }
    if needed > 0 && (needed as usize) < (1 << 16) {
        let mut buf = vec![0u8; needed as usize];
        if unsafe {
            GetTokenInformation(
                token.raw(),
                TokenUser,
                Some(buf.as_mut_ptr().cast()),
                needed,
                &mut needed,
            )
        }
        .is_ok()
        {
            let tu = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
            let mut name = [0u16; 256];
            let mut domain = [0u16; 256];
            let mut name_len = name.len() as u32;
            let mut domain_len = domain.len() as u32;
            let mut use_kind = SID_NAME_USE::default();

            if unsafe {
                LookupAccountSidW(
                    windows::core::PCWSTR::null(),
                    tu.User.Sid,
                    Some(windows::core::PWSTR(name.as_mut_ptr())),
                    &mut name_len,
                    Some(windows::core::PWSTR(domain.as_mut_ptr())),
                    &mut domain_len,
                    &mut use_kind,
                )
            }
            .is_ok()
            {
                let d = wide_to_string(&domain);
                let n = wide_to_string(&name);
                p.user = Some(if d.is_empty() { n } else { format!("{d}\\{n}") });
            }
        }
    }

    let mut elevation = TOKEN_ELEVATION::default();
    let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
    if unsafe {
        GetTokenInformation(
            token.raw(),
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            size,
            &mut size,
        )
    }
    .is_ok()
    {
        p.elevated = Some(elevation.TokenIsElevated != 0);
    }
}

/// List the modules mapped into a process.
unsafe fn enumerate_modules(h: HANDLE) -> Vec<LiveModule> {
    // Two passes: ask how much space the module list needs, then read it. Doing
    // it in one pass with a guessed size silently truncates on processes that
    // load hundreds of DLLs, which are exactly the interesting ones.
    let mut needed = 0u32;
    if unsafe { EnumProcessModulesEx(h, std::ptr::null_mut(), 0, &mut needed, LIST_MODULES_ALL) }
        .is_err()
        || needed == 0
    {
        return Vec::new();
    }

    let count = needed as usize / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();
    let mut mods = vec![windows::Win32::Foundation::HMODULE::default(); count];
    if unsafe {
        EnumProcessModulesEx(h, mods.as_mut_ptr(), needed, &mut needed, LIST_MODULES_ALL)
    }
    .is_err()
    {
        return Vec::new();
    }

    let actual = (needed as usize / std::mem::size_of::<windows::Win32::Foundation::HMODULE>())
        .min(mods.len());
    let mut out = Vec::with_capacity(actual);

    for m in mods.iter().take(actual) {
        let mut path_buf = [0u16; MAX_PATH as usize * 2];
        let n = unsafe { GetModuleFileNameExW(Some(h), Some(*m), &mut path_buf) };
        let path = (n > 0).then(|| wide_to_string(&path_buf[..n as usize]));

        let mut info = MODULEINFO::default();
        let (base, size) = if unsafe {
            GetModuleInformation(
                h,
                *m,
                &mut info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
        }
        .is_ok()
        {
            (info.lpBaseOfDll as u64, info.SizeOfImage)
        } else {
            (m.0 as u64, 0)
        };

        let name = path
            .as_deref()
            .and_then(|p| p.rsplit('\\').next())
            .unwrap_or("<unknown>")
            .to_string();

        out.push(LiveModule {
            name,
            path,
            base,
            size,
        });
    }
    out
}

/// Index processes by PID for parent lookup.
pub fn by_pid(procs: &[LiveProcess]) -> HashMap<u32, &LiveProcess> {
    procs.iter().map(|p| (p.pid, p)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerates_the_running_system() {
        let procs = enumerate(ProcessOptions {
            command_lines: true,
            modules: false,
            tokens: true,
        })
        .expect("enumeration must succeed on a live system");

        assert!(procs.len() > 10, "a running Windows host has many processes");

        // The collector's own test process must be in its own snapshot.
        let me = std::process::id();
        let mine = procs
            .iter()
            .find(|p| p.pid == me)
            .expect("the current process must appear in the snapshot");
        assert!(mine.create_time_filetime.is_some());
        assert!(mine.image_path.is_some());
        assert!(mine.user.is_some());
        assert!(
            mine.command_line.is_some(),
            "a process can always read its own command line"
        );
    }

    #[test]
    fn parent_references_are_never_self_referential() {
        let procs = enumerate(ProcessOptions {
            command_lines: false,
            modules: false,
            tokens: false,
        })
        .unwrap();
        for p in &procs {
            assert_ne!(p.ppid, Some(p.pid), "pid {} claims to be its own parent", p.pid);
        }
    }

    #[test]
    fn inaccessible_processes_are_recorded_not_dropped() {
        let procs = enumerate(ProcessOptions::default()).unwrap();
        // Without elevation some processes are unreadable. Whatever the number,
        // each one must still be present with its failure explained.
        for p in procs.iter().filter(|p| p.image_path.is_none() && p.pid != 0) {
            assert!(
                p.access_error.is_some(),
                "pid {} has no image path and no explanation",
                p.pid
            );
        }
        assert!(procs.iter().any(|p| p.pid == 4), "the System process is always present");
    }

    #[test]
    fn module_enumeration_finds_ntdll_in_our_own_process() {
        let procs = enumerate(ProcessOptions::default()).unwrap();
        let me = procs
            .iter()
            .find(|p| p.pid == std::process::id())
            .expect("self must be present");
        assert!(
            me.modules
                .iter()
                .any(|m| m.name.eq_ignore_ascii_case("ntdll.dll")),
            "every Windows process maps ntdll"
        );
        assert!(me.modules.iter().all(|m| m.base != 0));
    }
}
