//! M0b validation gate.
//!
//! Every third-party parser the plan leans on gets proven here before it becomes
//! a dependency of the collector: it must link, expose the API we assume, and
//! parse a real artifact wherever the current privilege level allows one. What
//! cannot be exercised unelevated (raw volume, VSS, registry hives) is recorded
//! as API-only so the gap stays visible instead of being assumed away.
//!
//! Samples live in `.gate-samples/` at the workspace root and are gitignored.

use std::fmt;
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Clone, Copy, PartialEq)]
enum Verdict {
    /// Exercised against a real artifact and produced correct output.
    Pass,
    /// Links and behaves correctly at the API boundary, but the artifact it
    /// really targets needs elevation we do not have here.
    ApiOnly,
    Fail,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Verdict::Pass => "PASS",
            Verdict::ApiOnly => "API-ONLY",
            Verdict::Fail => "FAIL",
        })
    }
}

struct Report {
    rows: Vec<(String, Verdict)>,
}

impl Report {
    fn new() -> Self {
        Self { rows: Vec::new() }
    }

    fn add(&mut self, subject: &str, v: Verdict, detail: impl AsRef<str>) {
        println!("[{:>8}] {:<22} {}", v.to_string(), subject, detail.as_ref());
        self.rows.push((subject.to_string(), v));
    }

    fn count(&self, v: Verdict) -> usize {
        self.rows.iter().filter(|(_, r)| *r == v).count()
    }
}

fn samples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(".gate-samples")
}

/// A structurally valid NTFS volume boot record, so the boot parser can be
/// exercised for real without the raw-volume handle that needs elevation.
fn synthetic_vbr() -> Vec<u8> {
    let mut s = vec![0u8; 512];
    s[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
    s[3..11].copy_from_slice(b"NTFS    ");
    s[11..13].copy_from_slice(&512u16.to_le_bytes()); // bytes per sector
    s[13] = 8; // sectors per cluster
    s[21] = 0xF8; // media descriptor
    s[24..26].copy_from_slice(&63u16.to_le_bytes());
    s[26..28].copy_from_slice(&255u16.to_le_bytes());
    s[40..48].copy_from_slice(&2_000_000u64.to_le_bytes()); // total sectors
    s[48..56].copy_from_slice(&786_432u64.to_le_bytes()); // $MFT LCN
    s[56..64].copy_from_slice(&2u64.to_le_bytes()); // $MFTMirr LCN
    s[64] = 0xF6; // clusters per MFT record: -10 => 1024 bytes
    s[68] = 1; // clusters per index buffer
    s[72..80].copy_from_slice(&0x1234_5678_9ABC_DEF0u64.to_le_bytes());
    s[510] = 0x55;
    s[511] = 0xAA;
    s
}

fn check_prefetch(r: &mut Report) {
    let dir = samples_dir();
    let samples: Vec<PathBuf> = fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.eq_ignore_ascii_case("pf"))
        })
        .collect();

    if samples.is_empty() {
        r.add("prefetch-core", Verdict::Fail, "no .pf samples staged");
        return;
    }

    let mut parsed = 0usize;
    let mut anomalies = 0usize;
    let mut headline = String::new();

    for path in &samples {
        let Ok(bytes) = fs::read(path) else { continue };
        match prefetch_core::parse(&bytes) {
            Ok(info) => {
                if headline.is_empty() {
                    headline = format!(
                        "{} v{} runs={} files={}",
                        info.executable,
                        info.version,
                        info.run_count,
                        info.filenames.len()
                    );
                }
                anomalies += prefetch_forensic::audit(&info).len();
                parsed += 1;
            }
            Err(e) => {
                r.add(
                    "prefetch-core",
                    Verdict::Fail,
                    format!("{}: {e:?}", path.display()),
                );
                return;
            }
        }
    }

    r.add(
        "prefetch-core",
        Verdict::Pass,
        format!("{parsed}/{} real .pf parsed; {headline}", samples.len()),
    );
    r.add(
        "prefetch-forensic",
        Verdict::Pass,
        format!("audit() over {parsed} samples yielded {anomalies} anomalies"),
    );
}

fn check_evtx(r: &mut Report) {
    let path = samples_dir().join("Application.evtx");
    if !path.exists() {
        r.add("evtx", Verdict::Fail, "no Application.evtx staged");
        return;
    }

    let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let started = Instant::now();
    let mut parser = match evtx::EvtxParser::from_path(&path) {
        Ok(p) => p,
        Err(e) => {
            r.add("evtx", Verdict::Fail, format!("open failed: {e}"));
            return;
        }
    };

    let (mut records, mut errors) = (0usize, 0usize);
    let mut first_ts = String::new();
    for rec in parser.records_json() {
        match rec {
            Ok(rec) => {
                if first_ts.is_empty() {
                    // evtx 0.12 hands back a `jiff::Timestamp`, which the
                    // timeline layer will convert to UTC nanoseconds.
                    first_ts = format!(
                        "{} ({} ns)",
                        rec.timestamp,
                        rec.timestamp.as_nanosecond()
                    );
                }
                records += 1;
            }
            Err(_) => errors += 1,
        }
    }

    if records == 0 {
        r.add("evtx", Verdict::Fail, "parsed zero records");
        return;
    }

    r.add(
        "evtx",
        Verdict::Pass,
        format!(
            "{records} records ({errors} err) from {:.1} MiB in {:.2}s; earliest {first_ts}",
            size as f64 / 1_048_576.0,
            started.elapsed().as_secs_f64()
        ),
    );
}

fn check_ntfs(r: &mut Report) {
    match ntfs_core::BootSector::parse(&synthetic_vbr()) {
        Ok(boot) => r.add(
            "ntfs-core",
            Verdict::Pass,
            format!(
                "VBR parsed: {} B/sector, mft_lcn={}",
                boot.bytes_per_sector, boot.mft_lcn
            ),
        ),
        Err(e) => r.add("ntfs-core", Verdict::Fail, format!("VBR parse: {e}")),
    }

    // The property the collector depends on is that hostile or truncated input
    // degrades instead of panicking, so junk is the right input here.
    let anomalies = ntfs_forensic::audit_record(&[0u8; 1024]);
    let (carved, stats) = ntfs_core::carve_mft_entries(&[0u8; 4096]);
    r.add(
        "ntfs-forensic",
        Verdict::Pass,
        format!(
            "audit_record survived junk ({} anomalies); carve returned {} entries, stats {stats:?}",
            anomalies.len(),
            carved.len()
        ),
    );

    match ntfs_core::NtfsFs::open(Cursor::new(vec![0u8; 8192])) {
        Ok(_) => r.add("ntfs-core::NtfsFs", Verdict::Fail, "accepted non-NTFS input"),
        Err(e) => r.add(
            "ntfs-core::NtfsFs",
            Verdict::ApiOnly,
            format!("rejects non-NTFS input ({e}); live volume needs elevation"),
        ),
    }
}

fn check_vshadow(r: &mut Report) {
    let mut buf = Cursor::new(vec![0u8; 0x4000]);
    let detail = match vshadow::VssVolume::new(&mut buf) {
        Ok(v) => format!("non-VSS buffer yields {} stores", v.store_count()),
        Err(e) => format!("rejects non-VSS buffer ({e})"),
    };
    r.add(
        "vshadow",
        Verdict::ApiOnly,
        format!("{detail}; real snapshots need elevation"),
    );
}

fn check_notatin(r: &mut Report) {
    let missing = samples_dir().join("__absent__.hve");
    match notatin::parser_builder::ParserBuilder::from_path(missing)
        .recover_deleted(true)
        .build()
    {
        Ok(_) => r.add("notatin", Verdict::Fail, "built a parser from a missing file"),
        Err(e) => r.add(
            "notatin",
            Verdict::ApiOnly,
            format!("builder links, errors on missing hive ({e}); hives need elevation"),
        ),
    }
}

fn check_container(r: &mut Report) {
    // The .tpv container is exactly these two working together: SQLite holding
    // zstd-compressed payloads, with FTS5 available for the text search the
    // viewer needs.
    let conn = match rusqlite::Connection::open_in_memory() {
        Ok(c) => c,
        Err(e) => {
            r.add("rusqlite", Verdict::Fail, format!("open: {e}"));
            return;
        }
    };

    if let Err(e) = conn.execute_batch(
        "CREATE TABLE payloads(id INTEGER PRIMARY KEY, z BLOB NOT NULL);
         CREATE VIRTUAL TABLE ft USING fts5(body);",
    ) {
        r.add("rusqlite", Verdict::Fail, format!("FTS5 unavailable: {e}"));
        return;
    }

    let sample = r#"{"EventID":4688,"Image":"C:\\Windows\\System32\\cmd.exe","User":"CORP\\svc"}"#
        .repeat(200);
    let compressed = match zstd::encode_all(sample.as_bytes(), 9) {
        Ok(c) => c,
        Err(e) => {
            r.add("zstd", Verdict::Fail, format!("encode: {e}"));
            return;
        }
    };

    if let Err(e) = conn.execute("INSERT INTO payloads(z) VALUES (?1)", [&compressed]) {
        r.add("rusqlite", Verdict::Fail, format!("blob insert: {e}"));
        return;
    }

    let stored: Vec<u8> = match conn.query_row("SELECT z FROM payloads WHERE id=1", [], |row| {
        row.get(0)
    }) {
        Ok(b) => b,
        Err(e) => {
            r.add("rusqlite", Verdict::Fail, format!("blob readback: {e}"));
            return;
        }
    };

    let roundtrips = zstd::decode_all(&stored[..])
        .map(|d| d == sample.as_bytes())
        .unwrap_or(false);
    let verdict = if roundtrips { Verdict::Pass } else { Verdict::Fail };

    r.add(
        "rusqlite",
        verdict,
        format!(
            "SQLite {} bundled, FTS5 present, blob roundtrip clean",
            rusqlite::version()
        ),
    );
    r.add(
        "zstd",
        verdict,
        format!(
            "{} B -> {} B ({:.1}x) on EVTX-shaped JSON",
            sample.len(),
            compressed.len(),
            sample.len() as f64 / compressed.len() as f64
        ),
    );
}

fn check_sysinfo(r: &mut Report) {
    let sys = sysinfo::System::new_all();
    let procs = sys.processes();
    if procs.is_empty() {
        r.add("sysinfo", Verdict::Fail, "enumerated zero processes");
        return;
    }
    let with_parent = procs.values().filter(|p| p.parent().is_some()).count();
    r.add(
        "sysinfo",
        Verdict::Pass,
        format!("{} processes, {with_parent} with a parent PID", procs.len()),
    );
}

fn main() {
    println!("TreePView M0b - crate validation gate");
    println!("samples: {}\n", samples_dir().display());

    let mut r = Report::new();
    check_prefetch(&mut r);
    check_evtx(&mut r);
    check_ntfs(&mut r);
    check_vshadow(&mut r);
    check_notatin(&mut r);
    check_container(&mut r);
    check_sysinfo(&mut r);

    println!(
        "\n{} pass, {} api-only, {} fail",
        r.count(Verdict::Pass),
        r.count(Verdict::ApiOnly),
        r.count(Verdict::Fail)
    );

    if r.count(Verdict::Fail) > 0 {
        std::process::exit(1);
    }
}
