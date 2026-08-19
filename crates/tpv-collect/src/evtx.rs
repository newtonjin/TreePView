//! Windows event logs into timeline events.
//!
//! High-value channels only, after the volatile snapshot. Optional channels
//! that are not installed (Sysmon, Defender) are skipped; access denied on a
//! required channel is a gap, never an abort.
//!
//! Event ids that already have a kind in the model are mapped (4688 → process
//! start, 4624 → logon, 7045 → service install, Sysmon 1/3/5/11). Everything
//! else is a `log_record` whose channel sits in `path` so the viewer can filter
//! it as a column.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use tpv_format::CaseWriter;
use tpv_model::{
    AccessMethod, Event, EventKind, ManifestEntry, Source, Timestamp, TsPrecision,
};

use crate::error::Result;

struct Channel {
    /// Channel name as Windows records it, stored on each event's `path`.
    name: &'static str,
    file: &'static str,
    /// Security / System / Application: missing or denied is a gap.
    /// Operational channels: absent is normal, not a failure.
    required: bool,
}

const CHANNELS: &[Channel] = &[
    Channel { name: "Security", file: "Security.evtx", required: true },
    Channel { name: "System", file: "System.evtx", required: true },
    Channel { name: "Application", file: "Application.evtx", required: true },
    Channel { name: "Windows PowerShell", file: "Windows PowerShell.evtx", required: false },
    Channel {
        name: "Microsoft-Windows-PowerShell/Operational",
        file: "Microsoft-Windows-PowerShell%4Operational.evtx",
        required: false,
    },
    Channel {
        name: "Microsoft-Windows-Sysmon/Operational",
        file: "Microsoft-Windows-Sysmon%4Operational.evtx",
        required: false,
    },
    Channel {
        name: "Microsoft-Windows-Windows Defender/Operational",
        file: "Microsoft-Windows-Windows Defender%4Operational.evtx",
        required: false,
    },
    Channel {
        name: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        file: "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
        required: false,
    },
    Channel {
        name: "Microsoft-Windows-TaskScheduler/Operational",
        file: "Microsoft-Windows-TaskScheduler%4Operational.evtx",
        required: false,
    },
];

/// Walk the high-value logs and write whatever can be read.
///
/// `max_records` caps each channel; `None` reads the whole file. Returns custody
/// warnings (truncated logs, denied required channels). Optional channels that
/// are simply not installed produce no warning.
pub fn write_logs(
    w: &mut CaseWriter,
    observed: Timestamp,
    max_records: Option<u64>,
    cancel: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    let dir = logs_dir();
    for ch in CHANNELS {
        let path = dir.join(ch.file);
        if !path.is_file() {
            if ch.required {
                let msg = format!("{} not present at {}", ch.name, path.display());
                warnings.push(msg.clone());
                w.add_manifest(&gap_manifest(&path, observed, msg))?;
            }
            continue;
        }
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            warnings.push("event log ingest interrupted by operator".into());
            break;
        }
        eprintln!("  event log {}...", ch.name);
        match ingest_file(w, &path, ch.name, observed, max_records, cancel) {
            Ok(stats) => {
                eprintln!("    {} records", stats.emitted);
                if stats.interrupted {
                    warnings.push(format!(
                        "{} interrupted by operator after {} records",
                        ch.name, stats.emitted
                    ));
                } else if stats.truncated {
                    warnings.push(format!(
                        "{} truncated after {} records (--evtx-cap); open the EVTX directly \
                         for the rest of the log",
                        ch.name, stats.emitted
                    ));
                }
                if stats.errors > 0 {
                    warnings.push(format!(
                        "{}: {} records could not be parsed and were skipped",
                        ch.name, stats.errors
                    ));
                }
            }
            Err(e) => {
                let msg = e.to_string();
                warnings.push(format!("{}: {msg}", ch.name));
                w.add_manifest(&gap_manifest(&path, observed, msg))?;
            }
        }
    }
    Ok(warnings)
}

pub struct IngestStats {
    pub emitted: u64,
    pub errors: u64,
    pub truncated: bool,
    pub interrupted: bool,
}

/// Parse one EVTX file into events. Used by the live collector and by tests.
pub fn ingest_file(
    w: &mut CaseWriter,
    path: &Path,
    channel_hint: &str,
    observed: Timestamp,
    max_records: Option<u64>,
    cancel: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<IngestStats> {
    let started = observed;
    let (sha256, size_bytes) = hash_file(path);
    let mut parser = evtx::EvtxParser::from_path(path).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
    })?;

    let mut emitted = 0u64;
    let mut errors = 0u64;
    let mut truncated = false;
    let mut interrupted = false;

    for rec in parser.records_json() {
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            interrupted = true;
            break;
        }
        match rec {
            Ok(rec) => {
                let ts = Timestamp::from_unix_nanos_i128(
                    rec.timestamp.as_nanosecond(),
                    TsPrecision::HundredNanos,
                );
                if let Some(event) = event_from_json(ts, rec.event_record_id, &rec.data, channel_hint)
                {
                    w.add_event(&event)?;
                    emitted += 1;
                }
                if let Some(cap) = max_records {
                    if cap > 0 && emitted >= cap {
                        truncated = true;
                        break;
                    }
                }
            }
            Err(_) => errors += 1,
        }
    }

    let finished = observed;
    let mut error = None;
    if interrupted {
        error = Some(format!("interrupted by operator after {emitted} records"));
    } else if truncated {
        let cap = max_records.unwrap_or(0);
        error = Some(format!("truncated after {emitted} records (cap {cap})"));
    }
    w.add_manifest(&ManifestEntry {
        source_path: path.display().to_string(),
        method: AccessMethod::Win32File,
        size_bytes,
        sha256,
        started,
        finished,
        events_emitted: emitted,
        error,
    })?;

    Ok(IngestStats {
        emitted,
        errors,
        truncated,
        interrupted,
    })
}

/// Turn one `records_json` payload into a timeline event.
pub fn event_from_json(ts: Timestamp, record_id: u64, json: &str, channel_hint: &str) -> Option<Event> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let event = v.get("Event").unwrap_or(&v);
    let system = event.get("System")?;
    let event_id = event_id(system)?;
    let channel = text_at(system, &["Channel"]).filter(|s| !s.is_empty()).unwrap_or_else(|| {
        if channel_hint.is_empty() {
            "Unknown".into()
        } else {
            channel_hint.to_string()
        }
    });
    let provider = provider_name(system);
    let computer = text_at(system, &["Computer"]);
    let data = flatten_event_data(event.get("EventData"));
    let user_data = flatten_event_data(event.get("UserData"));

    let mut fields = data;
    for (k, val) in user_data {
        fields.entry(k).or_insert(val);
    }

    let kind = classify(&channel, &provider, event_id);
    let pid = first_pid(&fields, &["NewProcessId", "ProcessId", "SourceProcessId", "ClientProcessId"]);
    let ppid = first_pid(&fields, &["ProcessId", "ParentProcessId", "ParentProcessID"]);
    // Parent and child share ProcessId on some events; only keep ppid when it
    // is actually a different field than the one used for pid.
    let ppid = match (pid, ppid) {
        (Some(a), Some(b)) if a == b => first_pid(&fields, &["ParentProcessId", "ParentProcessID"]),
        (_, p) => p,
    };

    let image = first_field(
        &fields,
        &[
            "NewProcessName",
            "Image",
            "ProcessName",
            "ImagePath",
            "ServiceFileName",
        ],
    );
    let user = account(&fields);
    let remote = remote_peer(&fields);
    let summary = format!(
        "[{event_id}] {}",
        summarise(kind, &channel, &provider, &fields, image.as_deref())
    );

    let mut ev = Event::new(ts, Source::Evtx, kind, summary)
        .with_path(&channel)
        .with_log_id(event_id)
        .with_payload(serde_json::json!({
            "event_id": event_id,
            "record_id": record_id,
            "provider": provider,
            "channel": channel,
            "computer": computer,
            "data": fields,
        }));
    if let Some(pid) = pid {
        ev.pid = Some(pid);
        ev.ppid = ppid;
        ev.image = image;
    } else {
        ev.image = image;
    }
    if let Some(user) = user {
        ev.user = Some(user);
    }
    if let Some(remote) = remote {
        ev.remote = Some(remote);
    }
    Some(ev)
}

fn classify(channel: &str, provider: &str, event_id: u32) -> EventKind {
    let sysmon = provider.contains("Sysmon") || channel.contains("Sysmon");
    if sysmon {
        return match event_id {
            1 => EventKind::ProcessStart,
            3 => EventKind::NetConnection,
            5 => EventKind::ProcessEnd,
            6 => EventKind::DriverLoad,
            11 => EventKind::FileCreate,
            13 => EventKind::RegistryWrite,
            _ => EventKind::LogRecord,
        };
    }
    match event_id {
        4688 => EventKind::ProcessStart,
        4689 => EventKind::ProcessEnd,
        4624 | 4625 | 4634 | 4647 | 4648 | 4778 | 4779 => EventKind::LogonSession,
        21 | 23 | 24 | 25 if channel.contains("LocalSessionManager") => EventKind::LogonSession,
        7045 => EventKind::ServiceInstall,
        7034 | 7035 | 7036 | 7040 => EventKind::ServiceState,
        4698 | 106 => EventKind::TaskRegister,
        _ => EventKind::LogRecord,
    }
}

fn summarise(
    kind: EventKind,
    channel: &str,
    provider: &str,
    fields: &BTreeMap<String, String>,
    image: Option<&str>,
) -> String {
    let base = image
        .and_then(|p| p.rsplit(['\\', '/']).next())
        .filter(|s| !s.is_empty());
    match kind {
        EventKind::ProcessStart => {
            let pid = fields
                .get("NewProcessId")
                .or_else(|| fields.get("ProcessId"))
                .map(|s| s.as_str())
                .unwrap_or("?");
            match fields.get("CommandLine").filter(|s| !s.is_empty()) {
                Some(cmd) => format!("{} (pid {pid}) started: {cmd}", base.unwrap_or("process")),
                None => format!("{} (pid {pid}) started", base.unwrap_or("process")),
            }
        }
        EventKind::ProcessEnd => format!("{} exited", base.unwrap_or("process")),
        EventKind::LogonSession => {
            let user = account(fields).unwrap_or_else(|| "(unknown user)".into());
            let typ = fields.get("LogonType").map(|s| s.as_str()).unwrap_or("?");
            match fields.get("IpAddress").filter(|s| !s.is_empty() && *s != "-") {
                Some(ip) => format!("logon {user} type {typ} from {ip}"),
                None => format!("logon {user} type {typ}"),
            }
        }
        EventKind::ServiceInstall => {
            let name = fields.get("ServiceName").map(|s| s.as_str()).unwrap_or("service");
            match fields.get("ImagePath") {
                Some(p) => format!("service {name} installed: {p}"),
                None => format!("service {name} installed"),
            }
        }
        EventKind::NetConnection => {
            let dest = remote_peer(fields).unwrap_or_default();
            format!("{} connected to {dest}", base.unwrap_or("process"))
        }
        _ => {
            let hint = fields
                .values()
                .find(|v| v.len() > 4 && v.len() < 120)
                .map(|s| s.as_str())
                .unwrap_or("");
            if hint.is_empty() {
                format!("{channel} {provider}")
            } else {
                format!("{channel}: {hint}")
            }
        }
    }
}

fn account(fields: &BTreeMap<String, String>) -> Option<String> {
    let user = first_field(fields, &["SubjectUserName", "TargetUserName", "User", "AccountName"])?;
    if user.is_empty() || user == "-" {
        return None;
    }
    let domain = first_field(
        fields,
        &["SubjectDomainName", "TargetDomainName", "AccountDomain"],
    );
    match domain {
        Some(d) if !d.is_empty() && d != "-" => Some(format!("{d}\\{user}")),
        _ => Some(user),
    }
}

fn remote_peer(fields: &BTreeMap<String, String>) -> Option<String> {
    if let Some(ip) = first_field(fields, &["DestinationIp", "DestAddress"]) {
        let port = first_field(fields, &["DestinationPort", "DestPort"]);
        return Some(match port {
            Some(p) => format!("{ip}:{p}"),
            None => ip,
        });
    }
    first_field(fields, &["IpAddress", "WorkstationName"]).filter(|s| s != "-" && s != "::1")
}

fn first_field(fields: &BTreeMap<String, String>, names: &[&str]) -> Option<String> {
    for n in names {
        if let Some(v) = fields.get(*n) {
            if !v.is_empty() {
                return Some(v.clone());
            }
        }
    }
    None
}

fn first_pid(fields: &BTreeMap<String, String>, names: &[&str]) -> Option<u32> {
    first_field(fields, names).as_deref().and_then(parse_pid)
}

fn parse_pid(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn event_id(system: &serde_json::Value) -> Option<u32> {
    as_text(system.get("EventID")?)?.parse().ok()
}

fn provider_name(system: &serde_json::Value) -> String {
    system
        .get("Provider")
        .and_then(|p| {
            p.get("#attributes")
                .and_then(|a| a.get("Name"))
                .and_then(as_text)
                .or_else(|| as_text(p))
        })
        .unwrap_or_default()
}

fn text_at(v: &serde_json::Value, path: &[&str]) -> Option<String> {
    let mut cur = v;
    for p in path {
        cur = cur.get(*p)?;
    }
    as_text(cur)
}

fn as_text(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Object(m) => m.get("#text").and_then(as_text),
        _ => None,
    }
}

fn flatten_event_data(data: Option<&serde_json::Value>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(data) = data else { return out };
    match data {
        serde_json::Value::Object(m) => {
            if let Some(serde_json::Value::Array(arr)) = m.get("Data") {
                for item in arr {
                    let name = item
                        .get("#attributes")
                        .and_then(|a| a.get("Name"))
                        .and_then(as_text);
                    let text = as_text(item);
                    if let (Some(n), Some(t)) = (name, text) {
                        out.insert(n, t);
                    }
                }
            } else {
                for (k, v) in m {
                    if k.starts_with('#') {
                        continue;
                    }
                    if let Some(t) = as_text(v) {
                        out.insert(k.clone(), t);
                    }
                }
            }
        }
        _ => {}
    }
    out
}

fn logs_dir() -> PathBuf {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    root.join("System32").join("winevt").join("Logs")
}

fn gap_manifest(path: &Path, observed: Timestamp, error: String) -> ManifestEntry {
    ManifestEntry {
        source_path: path.display().to_string(),
        method: AccessMethod::Win32File,
        size_bytes: 0,
        sha256: None,
        started: observed,
        finished: observed,
        events_emitted: 0,
        error: Some(error),
    }
}

fn hash_file(path: &Path) -> (Option<String>, u64) {
    match std::fs::File::open(path) {
        Ok(mut f) => match tpv_format::hash::sha256_stream(&mut f) {
            Ok((h, n)) => (Some(h), n),
            Err(_) => (None, 0),
        },
        Err(_) => (None, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpv_model::TzSource;

    fn ts() -> Timestamp {
        Timestamp::new(1_700_000_000_000_000_000, TsPrecision::HundredNanos, TzSource::NativeUtc)
    }

    fn wrap(system: &str, data: &str) -> String {
        format!(r##"{{"Event":{{"System":{system},"EventData":{data}}}}}"##)
    }

    #[test]
    fn process_creation_4688_becomes_a_process_start() {
        let json = wrap(
            r##"{"Provider":{"#attributes":{"Name":"Microsoft-Windows-Security-Auditing"}},
                "EventID":4688,"Channel":"Security","Computer":"HOST"}"##,
            r#"{"NewProcessId":"0x4d2","NewProcessName":"C:\\Windows\\System32\\cmd.exe",
                "ProcessId":"0x3e8","CommandLine":"cmd.exe /c whoami",
                "SubjectUserName":"alice","SubjectDomainName":"CORP"}"#,
        );
        let ev = event_from_json(ts(), 99, &json, "Security").unwrap();
        assert_eq!(ev.kind, EventKind::ProcessStart);
        assert_eq!(ev.source, Source::Evtx);
        assert_eq!(ev.pid, Some(1234));
        assert_eq!(ev.ppid, Some(1000));
        assert_eq!(ev.path.as_deref(), Some("Security"));
        assert_eq!(ev.user.as_deref(), Some(r"CORP\alice"));
        assert!(ev.summary.contains("[4688]"));
        assert!(ev.summary.contains("cmd.exe"));
        assert!(ev.summary.contains("whoami"));
        assert_eq!(ev.log_id, Some(4688));
    }

    #[test]
    fn event_id_object_form_is_accepted() {
        let json = wrap(
            r##"{"Provider":{"#attributes":{"Name":"Service Control Manager"}},
                "EventID":{"#text":"7045","#attributes":{"Qualifiers":"16384"}},
                "Channel":"System"}"##,
            r#"{"ServiceName":"EvilSvc","ImagePath":"C:\\Temp\\svc.exe"}"#,
        );
        let ev = event_from_json(ts(), 1, &json, "System").unwrap();
        assert_eq!(ev.kind, EventKind::ServiceInstall);
        assert_eq!(ev.log_id, Some(7045));
        assert!(ev.summary.contains("[7045]"));
        assert!(ev.summary.contains("EvilSvc"));
    }

    #[test]
    fn sysmon_network_is_a_connection_with_a_peer() {
        let json = wrap(
            r##"{"Provider":{"#attributes":{"Name":"Microsoft-Windows-Sysmon"}},
                "EventID":3,"Channel":"Microsoft-Windows-Sysmon/Operational"}"##,
            r#"{"Image":"C:\\Temp\\beacon.exe","ProcessId":"4242",
                "DestinationIp":"203.0.113.7","DestinationPort":"443"}"#,
        );
        let ev = event_from_json(ts(), 7, &json, "Microsoft-Windows-Sysmon/Operational").unwrap();
        assert_eq!(ev.kind, EventKind::NetConnection);
        assert_eq!(ev.log_id, Some(3));
        assert!(ev.summary.contains("[3]"));
        assert_eq!(ev.pid, Some(4242));
        assert_eq!(ev.remote.as_deref(), Some("203.0.113.7:443"));
    }

    #[test]
    fn logon_4624_carries_the_account_and_source_address() {
        let json = wrap(
            r##"{"Provider":{"#attributes":{"Name":"Microsoft-Windows-Security-Auditing"}},
                "EventID":4624,"Channel":"Security"}"##,
            r#"{"TargetUserName":"alice","TargetDomainName":"CORP",
                "LogonType":"10","IpAddress":"10.0.0.8"}"#,
        );
        let ev = event_from_json(ts(), 2, &json, "Security").unwrap();
        assert_eq!(ev.kind, EventKind::LogonSession);
        assert_eq!(ev.log_id, Some(4624));
        assert!(ev.summary.contains("[4624]"));
        assert_eq!(ev.user.as_deref(), Some(r"CORP\alice"));
        assert!(ev.summary.contains("type 10"));
        assert!(ev.summary.contains("10.0.0.8"));
    }

    #[test]
    fn named_data_array_is_flattened() {
        let json = wrap(
            r##"{"EventID":1,"Channel":"Application","Provider":{"#attributes":{"Name":"Test"}}}"##,
            r##"{"Data":[
                {"#attributes":{"Name":"Image"},"#text":"C:\\a.exe"},
                {"#attributes":{"Name":"ProcessId"},"#text":"99"}
            ]}"##,
        );
        let ev = event_from_json(ts(), 3, &json, "Application").unwrap();
        assert_eq!(ev.pid, Some(99));
        assert_eq!(ev.image.as_deref(), Some(r"C:\a.exe"));
    }

    #[test]
    fn unmapped_ids_stay_log_records_with_the_channel_as_path() {
        let json = wrap(
            r##"{"EventID":1000,"Channel":"Application",
                "Provider":{"#attributes":{"Name":"Application Error"}}}"##,
            r#"{"FaultingApplicationName":"foo.exe"}"#,
        );
        let ev = event_from_json(ts(), 4, &json, "Application").unwrap();
        assert_eq!(ev.kind, EventKind::LogRecord);
        assert_eq!(ev.path.as_deref(), Some("Application"));
        assert!(ev.summary.contains("1000"));
    }
}
