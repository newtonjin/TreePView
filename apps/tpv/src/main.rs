//! The TreePView collector.
//!
//! Deliberately austere. This binary runs on a machine someone may be actively
//! attacking, so it has no installer, no configuration file, no network calls
//! and no interactive prompts: everything it does is determined by its flags and
//! recorded in the case it produces.
//!
//! The inspection subcommands (`info`, `tree`, `verify`) exist so a responder
//! can sanity-check a case on the spot without the viewer, from the same single
//! binary they already copied onto the host.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tpv_collect::{CollectConfig, CollectError};
use tpv_format::{CaseReader, EventFilter, ProcessNode};
use tpv_model::{CollectionProfile, MemoryMode};

const VERSION: &str = concat!("tpv/", env!("CARGO_PKG_VERSION"));

#[derive(Parser)]
#[command(
    name = "tpv",
    version,
    about = "TreePView - forensic triage with a visual timeline",
    long_about = "Collects volatile state and forensic artifacts into a single portable .tpv case \
                  file, for analysis in the TreePView viewer on another machine."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Collect a case from this host.
    Collect {
        /// Where to write the case. A directory (or omitted) gets
        /// HOSTNAME-YYYYMMDDTHHMMSSZ.tpv. Must be on external media unless
        /// --allow-local-write is given.
        #[arg(short, long)]
        out: Option<PathBuf>,

        /// Permit writing onto the volume under examination. This alters
        /// allocation, $MFT and $UsnJrnl on that volume.
        #[arg(long)]
        allow_local_write: bool,

        /// Skip live state and collect only host identity. Useful for measuring
        /// the collector's own footprint.
        #[arg(long)]
        no_live: bool,

        /// Skip Windows event logs (Security, System, Application, and a small
        /// set of operational channels). Logs are collected by default.
        #[arg(long)]
        no_evtx: bool,

        /// Cap records read from each event-log channel. Omit to ingest the
        /// whole log. Use this on a huge Security.evtx when you need a faster
        /// triage rather than a complete copy.
        #[arg(long)]
        evtx_cap: Option<u64>,

        /// Skip Prefetch, scheduled tasks and SHA-256 of process images.
        #[arg(long)]
        no_disk: bool,

        /// Memory acquisition mode.
        #[arg(long, value_parser = parse_memory_mode, default_value = "regions-only")]
        memory: MemoryMode,

        /// Restrict memory acquisition to these PIDs. Repeatable.
        #[arg(long = "pid")]
        pids: Vec<u32>,

        /// Cap on collector resident memory, in MiB.
        #[arg(long, default_value_t = 512)]
        max_ram: u64,
    },

    /// Build a case from a memory image acquired elsewhere.
    ///
    /// Reads raw/dd, Windows crash dump, LiME and ELF core images. The kernel
    /// structure layout is recovered from the image itself, so no symbol
    /// download, profile or Python install is involved and the command works
    /// offline on a build that did not exist when this tool was compiled.
    Memory {
        /// The image to read. Opened read-only and never modified.
        image: PathBuf,

        /// Where to write the case.
        #[arg(short, long)]
        out: PathBuf,
    },

    /// Summarize a case: host, custody, counts and integrity.
    Info {
        case: PathBuf,
        /// Emit JSON instead of a human-readable summary.
        #[arg(long)]
        json: bool,
    },

    /// Print the process tree.
    Tree {
        case: PathBuf,
        /// Maximum depth to print.
        #[arg(long, default_value_t = 32)]
        depth: u32,
    },

    /// Check that the case contents still match the digest sealed at collection.
    Verify { case: PathBuf },
}

fn parse_memory_mode(s: &str) -> std::result::Result<MemoryMode, String> {
    MemoryMode::from_str_lossy(&s.replace('-', "_"))
        .ok_or_else(|| format!("unknown memory mode `{s}`"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Collect {
            out,
            allow_local_write,
            no_live,
            no_evtx,
            evtx_cap,
            no_disk,
            memory,
            pids,
            max_ram,
        } => collect(
            out,
            allow_local_write,
            no_live,
            no_evtx,
            evtx_cap,
            no_disk,
            memory,
            pids,
            max_ram,
        ),
        Command::Memory { image, out } => memory_image(image, out),
        Command::Info { case, json } => info(case, json),
        Command::Tree { case, depth } => tree(case, depth),
        Command::Verify { case } => verify(case),
    }
}

fn collect(
    out: Option<PathBuf>,
    allow_local_write: bool,
    no_live: bool,
    no_evtx: bool,
    evtx_cap: Option<u64>,
    no_disk: bool,
    memory: MemoryMode,
    pids: Vec<u32>,
    max_ram: u64,
) -> Result<()> {
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_flag = cancel.clone();
    let _ = ctrlc::set_handler(move || {
        eprintln!("\nCtrl+C — sealing the case…");
        cancel_flag.store(true, std::sync::atomic::Ordering::Relaxed);
    });

    let out = tpv_collect::resolve_collect_out(out);
    eprintln!("collecting to {}", out.display());
    let cfg = CollectConfig {
        out: out.clone(),
        tool_version: VERSION.into(),
        profile: CollectionProfile {
            memory,
            selected_pids: pids,
            live_state: !no_live,
            disk_artifacts: !no_disk,
            event_logs: !no_evtx,
            evtx_max_records: evtx_cap.filter(|n| *n > 0),
            prefer_vss: false,
            max_ram_mib: Some(max_ram),
            allow_local_write,
        },
        command_line: std::env::args().collect::<Vec<_>>().join(" "),
        cancel,
    };

    let summary = match tpv_collect::run(&cfg) {
        Ok(s) => s,
        // The refusal is the useful part of this error, so it is surfaced on its
        // own rather than buried under a generic failure message.
        Err(CollectError::UnsafeOutput { reason, .. }) => {
            eprintln!("\n{reason}");
            std::process::exit(2);
        }
        Err(e) => return Err(e.into()),
    };

    println!("case:     {}", summary.path.display());
    println!("events:   {}", summary.events);
    println!("entities: {}", summary.entities);
    println!("edges:    {}", summary.edges);
    println!("blobs:    {}", summary.blobs);
    println!("size:     {:.1} MiB", summary.file_size as f64 / 1_048_576.0);
    println!("content:  sha256:{}", summary.content_digest);
    println!("file:     sha256:{}", summary.file_digest);

    let reader = CaseReader::open(&summary.path)?;
    if let Some(custody) = reader.meta()?.custody {
        if !custody.warnings.is_empty() {
            println!("\ngaps:");
            for w in &custody.warnings {
                println!("  - {w}");
            }
        }
    }
    Ok(())
}

fn memory_image(image: PathBuf, out: PathBuf) -> Result<()> {
    let cfg = tpv_collect::memory::MemoryConfig {
        image: image.clone(),
        out: out.clone(),
        tool_version: VERSION.into(),
        command_line: std::env::args().collect::<Vec<_>>().join(" "),
    };

    eprintln!("reading {}", image.display());
    let summary = tpv_collect::memory::run(&cfg)?;

    println!("case:     {}", summary.path.display());
    println!("events:   {}", summary.events);
    println!("entities: {}", summary.entities);
    println!("content:  sha256:{}", summary.content_digest);

    let reader = CaseReader::open(&summary.path)?;
    if let Some(custody) = reader.meta()?.custody {
        for w in &custody.warnings {
            println!("\n! {w}");
        }
    }
    Ok(())
}

fn info(case: PathBuf, json: bool) -> Result<()> {
    let r = CaseReader::open(&case)
        .with_context(|| format!("opening {}", case.display()))?;
    let meta = r.meta()?;
    let counts = r.counts()?;

    if json {
        let out = serde_json::json!({
            "case_id": meta.case_id,
            "tool_version": meta.tool_version,
            "finalized": meta.finalized,
            "host": meta.host,
            "profile": meta.profile,
            "custody": meta.custody,
            "created": tpv_model::Timestamp::new(
                meta.created_utc_ns,
                tpv_model::TsPrecision::Millisecond,
                tpv_model::TzSource::NativeUtc,
            ).to_rfc3339(),
            "counts": {
                "events": counts.events,
                "entities": counts.entities,
                "edges": counts.edges,
                "blobs": counts.blobs,
                "manifest": counts.manifest_entries,
                "findings": counts.findings,
            },
            "time_span": r.time_span()?,
            "content_digest": meta.content_digest,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    println!("case      {}", meta.case_id);
    println!("tool      {}", meta.tool_version);
    println!(
        "host      {} ({} {}, {})",
        meta.host.hostname, meta.host.os_name, meta.host.os_version, meta.host.architecture
    );
    if let Some(tz) = &meta.host.timezone_name {
        println!(
            "timezone  {tz} (UTC offset bias {} min)",
            meta.host.utc_offset_minutes.unwrap_or(0)
        );
    }
    if !meta.finalized {
        println!("state     PARTIAL - collection did not finish; absences may not be real");
    }

    println!(
        "\nevents {}  entities {}  edges {}  blobs {}  artifacts {}  findings {}",
        counts.events,
        counts.entities,
        counts.edges,
        counts.blobs,
        counts.manifest_entries,
        counts.findings
    );

    if let Some((lo, hi)) = r.time_span()? {
        let at = |ns| {
            tpv_model::Timestamp::new(
                ns,
                tpv_model::TsPrecision::Millisecond,
                tpv_model::TzSource::NativeUtc,
            )
            .to_rfc3339()
        };
        println!("span   {} .. {}", at(lo), at(hi));
    }

    if let Some(c) = &meta.custody {
        println!(
            "\ncollector pid {} as {} ({})",
            c.collector_pid,
            c.run_as_user,
            if c.elevated { "elevated" } else { "not elevated" }
        );
        println!("command   {}", c.command_line);
        if !c.files_written.is_empty() {
            println!("wrote     {}", c.files_written.join(", "));
        }
        for w in &c.warnings {
            println!("warning   {w}");
        }
    }

    let manifest = r.manifest()?;
    if !manifest.is_empty() {
        println!("\nartifacts:");
        for m in &manifest {
            let status = match &m.error {
                Some(e) => format!("FAILED: {e}"),
                None => format!("{} events", m.events_emitted),
            };
            println!("  [{}] {} - {status}", m.method.as_str(), m.source_path);
        }
    }
    Ok(())
}

fn tree(case: PathBuf, depth: u32) -> Result<()> {
    let r = CaseReader::open(&case)
        .with_context(|| format!("opening {}", case.display()))?;
    let roots = r.process_tree()?;
    if roots.is_empty() {
        println!("(no processes in this case)");
        return Ok(());
    }
    for root in &roots {
        print_node(root, 0, depth);
    }

    let net = r.count_events(&EventFilter {
        network_only: true,
        ..Default::default()
    })?;
    println!("\n{net} network events across the tree");
    Ok(())
}

fn print_node(node: &ProcessNode, level: u32, max_depth: u32) {
    if level > max_depth {
        return;
    }
    let severity = node
        .max_severity
        .map(|s| format!(" [{}]", s.as_str()))
        .unwrap_or_default();
    println!(
        "{}{} (pid {}){}  {} events",
        "  ".repeat(level as usize),
        node.label,
        node.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
        severity,
        node.event_count
    );
    for child in &node.children {
        print_node(child, level + 1, max_depth);
    }
}

fn verify(case: PathBuf) -> Result<()> {
    let r = CaseReader::open(&case)
        .with_context(|| format!("opening {}", case.display()))?;

    let meta = r.meta()?;
    if !meta.finalized {
        println!("PARTIAL  collection was interrupted; no digest was sealed");
        std::process::exit(1);
    }

    if r.verify_content_digest()? {
        println!("OK       contents match the digest sealed at collection");
        println!("         sha256:{}", meta.content_digest.unwrap_or_default());
        Ok(())
    } else {
        println!("MISMATCH contents do not match the sealed digest");
        println!("         the case has been modified since it was collected");
        std::process::exit(1);
    }
}
