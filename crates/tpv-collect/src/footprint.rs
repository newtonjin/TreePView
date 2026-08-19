//! Keeping the collector out of its own evidence.
//!
//! Two rules, both of them requirements rather than polish. The case file must
//! not land on the volume under examination, because writing several hundred
//! megabytes there allocates clusters, updates `$MFT` and `$UsnJrnl`, and
//! destroys unallocated space that may hold the very artifacts being looked for.
//! And whatever the collector does touch has to be written down.

use std::path::{Path, PathBuf};

/// Why an output location was refused or accepted with reservations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocationVerdict {
    /// The output is on separate media. Nothing on the examined volume changes.
    External,
    /// The output is on the volume under examination, and the operator accepted
    /// that. The reason is recorded so the case explains its own contamination.
    LocalAccepted { warning: String },
    /// The output is on the volume under examination and was not authorized.
    Refused { reason: String },
}

/// Volume identifier used to compare the output path with the system volume.
///
/// On Windows this is the drive letter; elsewhere it is the mount root. Crude on
/// purpose: a wrong answer here should err towards refusing to write, and a
/// filesystem-level comparison would introduce exactly the API dependencies the
/// collector is trying to avoid.
fn volume_of(path: &Path) -> Option<String> {
    let s = path.to_string_lossy();
    #[cfg(windows)]
    {
        // Absolute paths look like `C:\...`; UNC paths are remote by definition.
        if s.starts_with("\\\\") {
            return Some("\\\\unc".into());
        }
        let bytes = s.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' {
            return Some((bytes[0] as char).to_ascii_uppercase().to_string());
        }
        None
    }
    #[cfg(not(windows))]
    {
        let _ = s;
        Some("/".into())
    }
}

/// The volume the examined system lives on.
fn system_volume() -> Option<String> {
    #[cfg(windows)]
    {
        std::env::var("SystemRoot")
            .ok()
            .and_then(|r| volume_of(Path::new(&r)))
    }
    #[cfg(not(windows))]
    {
        Some("/".into())
    }
}

/// Decide whether a case may be written to `out`.
///
/// Resolves the path against the current directory first, so a relative `--out`
/// is judged by where it actually lands rather than by how it was spelled.
pub fn check_output(out: &Path, allow_local_write: bool) -> LocationVerdict {
    let absolute = if out.is_absolute() {
        out.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|d| d.join(out))
            .unwrap_or_else(|_| out.to_path_buf())
    };

    let (Some(target), Some(system)) = (volume_of(&absolute), system_volume()) else {
        // Unable to tell where this lands. Refusing outright would break
        // legitimate uses on unusual paths, so it is allowed and flagged.
        return LocationVerdict::LocalAccepted {
            warning: format!(
                "could not determine which volume {} is on; assuming it may be the examined one",
                absolute.display()
            ),
        };
    };

    if target != system {
        return LocationVerdict::External;
    }

    if allow_local_write {
        LocationVerdict::LocalAccepted {
            warning: format!(
                "case written to {}, the volume under examination: \
                 allocation, $MFT and $UsnJrnl on that volume were altered by this collection",
                absolute.display()
            ),
        }
    } else {
        LocationVerdict::Refused {
            reason: format!(
                "{} is on the volume under examination ({target}:). Write to external or network \
                 media, or pass --allow-local-write to accept altering the evidence volume.",
                absolute.display()
            ),
        }
    }
}

/// Files the collector created, for the custody record.
#[derive(Debug, Default, Clone)]
pub struct Footprint {
    pub files_written: Vec<PathBuf>,
    pub warnings: Vec<String>,
}

impl Footprint {
    pub fn wrote(&mut self, path: impl Into<PathBuf>) {
        self.files_written.push(path.into());
    }

    pub fn warn(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn external_media_is_accepted_without_comment() {
        // Pick a drive letter that is not the system volume.
        let system = system_volume().unwrap();
        let other = if system == "Z" { "Y" } else { "Z" };
        let out = PathBuf::from(format!("{other}:\\cases\\incident.tpv"));
        assert_eq!(check_output(&out, false), LocationVerdict::External);
    }

    #[cfg(windows)]
    #[test]
    fn the_examined_volume_is_refused_by_default() {
        let system = system_volume().unwrap();
        let out = PathBuf::from(format!("{system}:\\Users\\Public\\incident.tpv"));
        match check_output(&out, false) {
            LocationVerdict::Refused { reason } => {
                assert!(reason.contains("--allow-local-write"), "{reason}");
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn the_examined_volume_is_allowed_with_an_explicit_flag_and_a_warning() {
        let system = system_volume().unwrap();
        let out = PathBuf::from(format!("{system}:\\Users\\Public\\incident.tpv"));
        match check_output(&out, true) {
            LocationVerdict::LocalAccepted { warning } => {
                assert!(warning.contains("$UsnJrnl"), "{warning}");
            }
            other => panic!("expected acceptance with a warning, got {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn network_paths_count_as_external() {
        let out = PathBuf::from(r"\\evidence-server\share\incident.tpv");
        assert_eq!(check_output(&out, false), LocationVerdict::External);
    }

    #[test]
    fn footprint_records_what_was_touched() {
        let mut f = Footprint::default();
        f.wrote("E:\\case.tpv");
        f.warn("something to tell the analyst");
        assert_eq!(f.files_written.len(), 1);
        assert_eq!(f.warnings.len(), 1);
    }
}
