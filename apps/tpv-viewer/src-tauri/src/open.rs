//! Opening whatever the analyst pointed the viewer at.
//!
//! The viewer is the analysis box, so it has to accept both a finished `.tpv`
//! case and the raw captures that have not been turned into one yet. Sniffing
//! the file itself, rather than trusting the extension, is what lets a crash
//! dump named `memory.img` and a case named without `.tpv` both just open.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use tpv_collect::memory::MemoryConfig;
use tpv_format::CaseReader;

use crate::error::{Result, ViewerError};

const VERSION: &str = concat!("tpv-viewer/", env!("CARGO_PKG_VERSION"));

/// SQLite's well-known header, including the trailing NUL.
const SQLITE: &[u8; 16] = b"SQLite format 3\0";

/// Extensions that are memory images even when the bytes have no magic.
///
/// A flat `dd`/`winpmem --format raw` capture has none; the extension is the
/// only hint short of trying to recover a page-table root.
const MEMORY_EXT: &[&str] = &[
    "raw", "dmp", "dump", "mem", "vmem", "lime", "dd", "bin", "core", "elf", "sav", "img",
];

/// Open a case, or analyse a memory image into one and then open that.
pub fn open_any(path: &Path) -> Result<CaseReader> {
    if !path.is_file() {
        return Err(ViewerError::UnsupportedFile {
            path: path.to_path_buf(),
            reason: "path is not a file".into(),
        });
    }

    match sniff(path)? {
        Kind::Case => open_case_file(path),
        Kind::Memory => open_memory_image(path),
        Kind::Unknown { hint } => Err(ViewerError::UnsupportedFile {
            path: path.to_path_buf(),
            reason: hint,
        }),
    }
}

/// Prefer a writable handle so findings can be regenerated; a read-only USB
/// still opens, just without rewriting the derived table.
fn open_case_file(path: &Path) -> Result<CaseReader> {
    match CaseReader::open_for_findings(path) {
        Ok(mut reader) => {
            let _ = reader.regenerate_findings();
            Ok(reader)
        }
        Err(_) => Ok(CaseReader::open(path)?),
    }
}

#[derive(Debug)]
enum Kind {
    Case,
    Memory,
    Unknown { hint: String },
}

fn sniff(path: &Path) -> Result<Kind> {
    let mut hdr = [0u8; 16];
    let n = File::open(path)?.read(&mut hdr)?;
    let bytes = &hdr[..n];

    if bytes.len() == 16 && bytes == SQLITE {
        return Ok(Kind::Case);
    }
    if looks_like_memory_magic(bytes) || has_memory_extension(path) {
        return Ok(Kind::Memory);
    }
    Ok(Kind::Unknown {
        hint: "open a .tpv case or a memory image (.raw, crash dump, LiME, ELF core)".into(),
    })
}

fn looks_like_memory_magic(b: &[u8]) -> bool {
    b.len() >= 8 && &b[0..8] == b"PAGEDU64"
        || b.len() >= 4 && b[0..4] == [0x45, 0x4D, 0x69, 0x4C] // "LiME" little-endian u32
        || b.len() >= 4 && b[0..4] == *b"LiME"
        || b.len() >= 4 && b[0..4] == *b"\x7fELF"
}

fn has_memory_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| MEMORY_EXT.iter().any(|k| e.eq_ignore_ascii_case(k)))
        .unwrap_or(false)
}

/// Where a derived case for this image would live, next to the image.
///
/// `memdump.raw` becomes `memdump.raw.tpv`, not `memdump.tpv`, so a live-collected
/// case sitting in the same folder is not mistaken for the analysis of this file.
pub fn sibling_case_path(image: &Path) -> PathBuf {
    let mut name = image.file_name().unwrap_or_default().to_os_string();
    name.push(".tpv");
    image.with_file_name(name)
}

fn temp_case_path(image: &Path) -> PathBuf {
    let name = sibling_case_path(image)
        .file_name()
        .unwrap_or_default()
        .to_owned();
    let dir = std::env::temp_dir().join("treepview");
    let _ = std::fs::create_dir_all(&dir);
    dir.join(name)
}

fn open_memory_image(path: &Path) -> Result<CaseReader> {
    let derived = sibling_case_path(path);
    if derived.exists() {
        if let Ok(reader) = open_case_file(&derived) {
            return Ok(reader);
        }
        return analyse(path, temp_case_path(path));
    }

    match analyse(path, derived.clone()) {
        Ok(reader) => Ok(reader),
        Err(e) if e.is_unwritable() => analyse(path, temp_case_path(path)),
        Err(e) => Err(e),
    }
}

fn analyse(image: &Path, out: PathBuf) -> Result<CaseReader> {
    tpv_collect::memory::run(&MemoryConfig {
        image: image.to_path_buf(),
        out: out.clone(),
        tool_version: VERSION.into(),
        command_line: format!("tpv-viewer {}", image.display()),
    })?;
    Ok(open_case_file(&out)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tpv_format::{CaseInit, CaseWriter};
    use tpv_model::{
        CollectionProfile, Custody, HostInfo, ReferenceClock, Timestamp, TsPrecision, TzSource,
    };

    fn ts(n: i64) -> Timestamp {
        Timestamp::new(n, TsPrecision::Millisecond, TzSource::NativeUtc)
    }

    fn write_case(path: &Path) {
        let w = CaseWriter::create(
            path,
            CaseInit {
                case_id: tpv_model::CaseId::generate(),
                tool_version: "tpv-test".into(),
                host: HostInfo {
                    hostname: "TARGET".into(),
                    os_name: "Windows".into(),
                    os_version: "10".into(),
                    architecture: "x86_64".into(),
                    domain: None,
                    machine_id: None,
                    timezone_name: None,
                    utc_offset_minutes: None,
                    boot_time: None,
                },
                clock: ReferenceClock {
                    host_utc: ts(1),
                    monotonic_uptime_ms: None,
                },
                profile: CollectionProfile::default(),
            },
        )
        .unwrap();
        w.finish(Custody {
            collector_version: "tpv-test".into(),
            collector_pid: 1,
            collector_image: "tpv.exe".into(),
            collector_sha256: None,
            command_line: "tpv collect".into(),
            started: ts(1),
            finished: ts(2),
            run_as_user: "SYSTEM".into(),
            elevated: true,
            files_written: vec![],
            warnings: vec![],
        })
        .unwrap();
    }

    #[test]
    fn a_case_opens_regardless_of_its_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence.bin");
        write_case(&path);
        let reader = open_any(&path).unwrap();
        assert_eq!(reader.meta().unwrap().host.hostname, "TARGET");
    }

    #[test]
    fn a_random_text_file_is_refused_rather_than_treated_as_a_flat_image() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.txt");
        std::fs::write(&path, "this is not evidence").unwrap();
        match open_any(&path) {
            Err(ViewerError::UnsupportedFile { reason, .. }) => {
                assert!(reason.contains(".tpv"), "{reason}");
            }
            Ok(_) => panic!("expected UnsupportedFile, opened as a case"),
            Err(other) => panic!("expected UnsupportedFile, got {other}"),
        }
    }

    #[test]
    fn a_raw_extension_is_sniffed_as_memory_even_without_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memdump.raw");
        // Too small to analyse, but large enough to have no SQLite header.
        std::fs::write(&path, vec![0u8; 64]).unwrap();
        match sniff(&path).unwrap() {
            Kind::Memory => {}
            other => panic!("expected Memory, got {other:?}"),
        }
    }

    #[test]
    fn the_derived_case_sits_next_to_the_image_without_clobbering_a_stem_match() {
        let path = Path::new(r"E:\evidence\memdump.raw");
        assert_eq!(
            sibling_case_path(path),
            PathBuf::from(r"E:\evidence\memdump.raw.tpv")
        );
    }

    #[test]
    fn opening_a_raw_reuses_a_derived_case_already_sitting_next_to_it() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("memdump.raw");
        std::fs::write(&image, vec![0u8; 64]).unwrap();
        write_case(&sibling_case_path(&image));
        let reader = open_any(&image).unwrap();
        assert_eq!(reader.meta().unwrap().host.hostname, "TARGET");
    }

    #[test]
    fn a_crash_dump_magic_is_recognised_without_the_usual_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hiberfil.sys");
        let mut f = File::create(&path).unwrap();
        f.write_all(b"PAGEDU64").unwrap();
        f.write_all(&[0u8; 24]).unwrap();
        match sniff(&path).unwrap() {
            Kind::Memory => {}
            other => panic!("expected Memory, got {other:?}"),
        }
    }
}
