//! Autostart extensibility points.
//!
//! A deliberately small, well-understood set rather than an attempt to match
//! Autoruns' hundreds of locations. Each entry here is read live through the
//! registry API; the authoritative, lock-free version comes from the hive parser
//! in M3. Collecting them now means the live snapshot already answers "what
//! starts with this machine" without waiting for raw volume access.

#![allow(unsafe_code)]

use windows::core::PCWSTR;
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    KEY_READ, KEY_WOW64_64KEY, REG_EXPAND_SZ, REG_SZ,
};

use crate::sys::{to_wide, wide_to_string};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AutorunRecord {
    pub hive: String,
    pub key: String,
    pub value_name: String,
    pub value: String,
}

impl AutorunRecord {
    /// Full registry path, as an analyst would write it.
    pub fn full_key(&self) -> String {
        format!("{}\\{}", self.hive, self.key)
    }
}

/// How a key's unnamed default value is labelled, matching regedit.
pub const DEFAULT_VALUE_NAME: &str = "(Default)";

/// The autostart keys collected live.
const RUN_KEYS: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
];

/// Read every configured autostart entry from both machine and user hives.
pub fn enumerate() -> (Vec<AutorunRecord>, Vec<String>) {
    let mut out = Vec::new();
    let mut warnings = Vec::new();

    for (hive, label) in [
        (HKEY_LOCAL_MACHINE, "HKLM"),
        (HKEY_CURRENT_USER, "HKCU"),
    ] {
        for key in RUN_KEYS {
            match read_values(hive, key) {
                Ok(values) => out.extend(values.into_iter().map(|(name, value)| AutorunRecord {
                    hive: label.to_string(),
                    key: (*key).to_string(),
                    value_name: name,
                    value,
                })),
                // A missing key is the normal case for most of this list, so
                // only genuine access failures are reported.
                Err(RegError::NotFound) => {}
                Err(RegError::Other(e)) => {
                    warnings.push(format!("{label}\\{key}: {e}"));
                }
            }
        }
    }
    (out, warnings)
}

#[derive(Debug)]
enum RegError {
    NotFound,
    Other(String),
}

fn read_values(hive: HKEY, subkey: &str) -> Result<Vec<(String, String)>, RegError> {
    let wide = to_wide(subkey);
    let mut key = HKEY::default();

    // Force the 64-bit view so a 32-bit build of the collector does not silently
    // read the WOW6432Node redirect and report a different machine than the one
    // it is running on.
    let rc = unsafe {
        RegOpenKeyExW(
            hive,
            PCWSTR(wide.as_ptr()),
            None,
            KEY_READ | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    if rc.is_err() {
        return Err(if rc.0 == 2 {
            RegError::NotFound
        } else {
            RegError::Other(format!("RegOpenKeyEx returned {}", rc.0))
        });
    }

    let mut out = Vec::new();
    let mut index = 0u32;
    loop {
        let mut name = [0u16; 512];
        let mut name_len = name.len() as u32;
        let mut data = [0u8; 8192];
        let mut data_len = data.len() as u32;
        let mut kind = 0u32;

        let rc = unsafe {
            RegEnumValueW(
                key,
                index,
                Some(windows::core::PWSTR(name.as_mut_ptr())),
                &mut name_len,
                None,
                Some(&mut kind),
                Some(data.as_mut_ptr()),
                Some(&mut data_len),
            )
        };
        if rc.is_err() {
            break;
        }

        if kind == REG_SZ.0 || kind == REG_EXPAND_SZ.0 {
            let chars = (data_len as usize) / 2;
            let units: Vec<u16> = data[..chars * 2]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();

            // A key's default value has an empty name. It carries real weight in
            // several autostart locations, so it is labelled the way regedit
            // shows it rather than emitted as a blank the analyst has to guess at.
            let value_name = match wide_to_string(&name[..name_len as usize]) {
                s if s.is_empty() => DEFAULT_VALUE_NAME.to_string(),
                s => s,
            };
            out.push((value_name, wide_to_string(&units)));
        }
        index += 1;
        if index > 4096 {
            break;
        }
    }

    unsafe {
        let _ = RegCloseKey(key);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerates_without_warnings_on_a_healthy_host() {
        let (entries, warnings) = enumerate();
        assert!(
            warnings.is_empty(),
            "the standard Run keys should be readable by any user: {warnings:?}"
        );
        // Entry count varies by machine, so only the shape is asserted.
        for e in &entries {
            assert!(
                !e.value_name.is_empty(),
                "a default value must be labelled, not left blank"
            );
            assert!(e.full_key().starts_with("HK"));
        }
    }

    #[test]
    fn the_windows_key_default_value_is_labelled() {
        // `HKLM\...\Windows NT\CurrentVersion\Windows` carries a default value on
        // every Windows install, which is what surfaced the blank-name case.
        let values = read_values(
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
        )
        .expect("the key exists on every Windows host");

        assert!(
            values.iter().all(|(name, _)| !name.is_empty()),
            "no value may be emitted with an empty name"
        );
    }

    #[test]
    fn a_missing_key_is_not_an_error() {
        match read_values(HKEY_LOCAL_MACHINE, r"Software\TreePViewDefinitelyNotPresent") {
            Err(RegError::NotFound) => {}
            Err(RegError::Other(e)) => panic!("expected NotFound, got {e}"),
            Ok(_) => panic!("a nonexistent key must not return values"),
        }
    }
}
