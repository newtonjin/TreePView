//! Local, regenerable detections over a finished case.
//!
//! These rules are triage hints, not a detection product. Each finding names
//! the events it rests on so an analyst can discard the opinion without
//! touching the evidence. Re-running replaces the table wholesale.

use tpv_model::{Confidence, EdgeState, EventKind, Finding, Severity};

use crate::error::Result;
use crate::reader::{CaseReader, EventFilter, EventRow};

const PER_RULE: u32 = 40;

/// Scan the open case and return supported findings, newest rules last.
pub fn scan(r: &CaseReader) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    out.extend(service_installs(r)?);
    out.extend(autoruns(r)?);
    out.extend(orphan_processes(r)?);
    out.extend(encoded_powershell(r)?);
    out.extend(logon_type_10(r)?);
    out.extend(unlinked_eprocess(r)?);
    out.extend(forest_indicators(r)?);
    out.extend(log_cleared(r)?);
    out.retain(|f| f.is_supported());
    Ok(out)
}

fn service_installs(r: &CaseReader) -> Result<Vec<Finding>> {
    let rows = kind(r, EventKind::ServiceInstall)?;
    Ok(rows
        .into_iter()
        .map(|e| {
            Finding::new(
                "evtx.service_install",
                Severity::High,
                Confidence::High,
                "Service installed (7045)",
                e.summary.clone(),
                vec![e.id],
            )
            .maybe_about(e.entity_key)
        })
        .collect())
}

fn autoruns(r: &CaseReader) -> Result<Vec<Finding>> {
    let rows = kind(r, EventKind::AutostartEntry)?;
    Ok(rows
        .into_iter()
        .map(|e| {
            Finding::new(
                "live.autostart_entry",
                Severity::Medium,
                Confidence::High,
                "Run-key autostart",
                e.summary.clone(),
                vec![e.id],
            )
            .maybe_about(e.entity_key)
        })
        .collect())
}

fn orphan_processes(r: &CaseReader) -> Result<Vec<Finding>> {
    let rows = kind(r, EventKind::ProcessSnapshot)?;
    let pids: std::collections::HashSet<u32> = rows.iter().filter_map(|e| e.pid).collect();
    Ok(rows
        .into_iter()
        .filter(|e| {
            let pid = e.pid.unwrap_or(0);
            if pid == 0 || pid == 4 {
                return false;
            }
            match e.ppid {
                Some(ppid) if ppid != 0 && ppid != 4 => !pids.contains(&ppid),
                _ => false,
            }
        })
        .map(|e| {
            Finding::new(
                "live.process_orphan",
                Severity::Medium,
                Confidence::Medium,
                "Process parent is not in the snapshot",
                format!(
                    "{} (pid {} ppid {}) has no matching parent in this case",
                    e.image.as_deref().unwrap_or(&e.summary),
                    e.pid.unwrap_or(0),
                    e.ppid.unwrap_or(0)
                ),
                vec![e.id],
            )
            .maybe_about(e.entity_key)
        })
        .collect())
}

fn encoded_powershell(r: &CaseReader) -> Result<Vec<Finding>> {
    let mut rows = kind(r, EventKind::ProcessStart)?;
    rows.extend(kind(r, EventKind::ProcessSnapshot)?);
    let mut out = Vec::new();
    for e in rows {
        let mut blob = e.summary.clone();
        if let Ok(Some(p)) = r.payload(e.id) {
            blob.push(' ');
            blob.push_str(&p.to_string());
        }
        if !looks_encoded_powershell(&blob) {
            continue;
        }
        out.push(
            Finding::new(
                "exec.encoded_powershell",
                Severity::High,
                Confidence::Medium,
                "Encoded PowerShell command line",
                e.summary.clone(),
                vec![e.id],
            )
            .maybe_about(e.entity_key),
        );
    }
    Ok(out)
}

fn logon_type_10(r: &CaseReader) -> Result<Vec<Finding>> {
    let rows = kind(r, EventKind::LogonSession)?;
    Ok(rows
        .into_iter()
        .filter(|e| is_logon_type_10(&e.summary))
        .map(|e| {
            Finding::new(
                "evtx.logon_type_10",
                Severity::Medium,
                Confidence::High,
                "Remote interactive logon (type 10)",
                e.summary.clone(),
                vec![e.id],
            )
            .maybe_about(e.entity_key)
        })
        .collect())
}

fn unlinked_eprocess(r: &CaseReader) -> Result<Vec<Finding>> {
    let rows = r.events(
        &EventFilter {
            text: Some("MISSING from the kernel".into()),
            ..Default::default()
        },
        PER_RULE,
        0,
    )?;
    Ok(rows
        .into_iter()
        .filter(|e| e.summary.contains("MISSING from the kernel"))
        .map(|e| {
            Finding::new(
                "mem.eprocess_unlinked",
                Severity::Critical,
                Confidence::High,
                "Process missing from the kernel list",
                e.summary.clone(),
                vec![e.id],
            )
            .maybe_about(e.entity_key)
        })
        .collect())
}

fn log_cleared(r: &CaseReader) -> Result<Vec<Finding>> {
    let rows = r.events(
        &EventFilter {
            log_ids: vec![1102, 104],
            ..Default::default()
        },
        PER_RULE,
        0,
    )?;
    Ok(rows
        .into_iter()
        .map(|e| {
            Finding::new(
                "LOG_CLEARED",
                Severity::High,
                Confidence::High,
                "Event log cleared",
                e.summary.clone(),
                vec![e.id],
            )
            .maybe_about(e.entity_key)
        })
        .collect())
}

fn forest_indicators(r: &CaseReader) -> Result<Vec<Finding>> {
    let forest = r.process_forest()?;
    let by_id: std::collections::HashMap<_, _> =
        forest.instances.iter().map(|i| (&i.id, i)).collect();
    let mut out = Vec::new();
    for inst in &forest.instances {
        let evidence = inst.event_ids.clone();
        if evidence.is_empty() {
            continue;
        }
        let key = inst
            .entity_keys
            .iter()
            .next()
            .cloned()
            .or_else(|| Some(tpv_model::entity_key_for(inst.pid, inst.start_utc_ns)));
        let image = inst.image_path.as_deref().unwrap_or("process");
        for ind in &inst.indicators {
            let (sev, title, detail) = match ind.as_str() {
                "CMDLINE_PEB_MISMATCH" => (
                    Severity::High,
                    "PEB command line disagrees with 4688",
                    format!(
                        "{image} (pid {}): PEB argv was overwritten after start, or the two sources never agreed",
                        inst.pid
                    ),
                ),
                "PROC_UNLINKED" => (
                    Severity::Critical,
                    "Process in memory, missing from the live list",
                    format!("{image} (pid {}) is a DKOM / hidden-process candidate", inst.pid),
                ),
                "MASQUERADE_PATH" => (
                    Severity::High,
                    "System binary name running outside a system directory",
                    format!("{image} (pid {})", inst.pid),
                ),
                "SHORT_LIVED_SHELL" => (
                    Severity::Medium,
                    "Shell lived less than five seconds",
                    format!("{image} (pid {})", inst.pid),
                ),
                _ => continue,
            };
            out.push(
                Finding::new(ind, sev, Confidence::High, title, detail, evidence.clone())
                    .maybe_about(key.clone()),
            );
        }
        match inst.parent_edge {
            EdgeState::Impossible => out.push(
                Finding::new(
                    "PID_RECYCLED",
                    Severity::Medium,
                    Confidence::High,
                    "Parent PID is not resolvable (recycled)",
                    format!(
                        "{image} (pid {}) claimed PPID {:?} after that PID's previous occupant had exited; the edge was not drawn",
                        inst.pid, inst.claimed_ppid
                    ),
                    evidence.clone(),
                )
                .maybe_about(key.clone()),
            ),
            EdgeState::Orphaned if inst.pid > 4 => out.push(
                Finding::new(
                    "PROC_ORPHANED",
                    Severity::Low,
                    Confidence::Medium,
                    "Parent PID matches no instance in this case",
                    format!("{image} (pid {}) claimed PPID {:?}", inst.pid, inst.claimed_ppid),
                    evidence.clone(),
                )
                .maybe_about(key.clone()),
            ),
            _ => {}
        }
        if let Some(pid) = &inst.parent_id {
            if let Some(parent) = by_id.get(pid) {
                let cmd = inst
                    .fields
                    .iter()
                    .find(|f| f.field == "command_line")
                    .map(|f| f.value.as_str());
                if suspect_parent(
                    parent.image_path.as_deref(),
                    inst.image_path.as_deref(),
                    cmd,
                ) {
                    out.push(
                        Finding::new(
                            "SUSPECT_PARENT",
                            Severity::High,
                            Confidence::Medium,
                            "Unusual parent → child pair",
                            format!(
                                "{} → {image} (pid {} ← {})",
                                parent.image_path.as_deref().unwrap_or("parent"),
                                inst.pid,
                                parent.pid
                            ),
                            evidence,
                        )
                        .maybe_about(key),
                    );
                }
            }
        }
    }
    Ok(out)
}

fn suspect_parent(parent: Option<&str>, child: Option<&str>, child_cmd: Option<&str>) -> bool {
    let pb = basename(parent);
    let cb = basename(child);
    if pb.is_empty() || cb.is_empty() {
        return false;
    }
    let office = matches!(
        pb.as_str(),
        "winword.exe" | "excel.exe" | "powerpnt.exe" | "outlook.exe" | "onenote.exe"
    );
    let shell = matches!(
        cb.as_str(),
        "cmd.exe" | "powershell.exe" | "pwsh.exe" | "wscript.exe" | "cscript.exe" | "mshta.exe"
    );
    if pb == "services.exe" && shell {
        return true;
    }
    if office && shell {
        return true;
    }
    if pb == "explorer.exe" && cb == "rundll32.exe" {
        let args = child_cmd.unwrap_or("");
        return args.contains(' ') && args.len() > "rundll32.exe".len();
    }
    false
}

fn basename(path: Option<&str>) -> String {
    path.and_then(|p| p.rsplit(['\\', '/']).next())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn kind(r: &CaseReader, k: EventKind) -> Result<Vec<EventRow>> {
    r.events(
        &EventFilter {
            kinds: vec![k],
            ..Default::default()
        },
        PER_RULE,
        0,
    )
}

pub(crate) fn looks_encoded_powershell(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains("-encodedcommand")
        || l.contains("frombase64string")
        || l.contains("-enc ")
        || l.contains("-enc'")
        || l.contains("-enc\"")
}

fn is_logon_type_10(summary: &str) -> bool {
    if let Some(rest) = summary.split(" type ").nth(1) {
        rest.trim_start().starts_with("10")
            && rest
                .trim_start()
                .chars()
                .nth(2)
                .is_none_or(|c| !c.is_ascii_digit())
    } else {
        false
    }
}

trait MaybeAbout {
    fn maybe_about(self, key: Option<String>) -> Finding;
}

impl MaybeAbout for Finding {
    fn maybe_about(self, key: Option<String>) -> Finding {
        match key {
            Some(k) => self.about(k),
            None => self,
        }
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn encoded_powershell_markers() {
        assert!(looks_encoded_powershell(
            r#"powershell -EncodedCommand AQID"#
        ));
        assert!(looks_encoded_powershell("FromBase64String('YQ==')"));
        assert!(!looks_encoded_powershell("powershell -File script.ps1"));
    }

    #[test]
    fn logon_type_10_is_not_type_100() {
        assert!(is_logon_type_10("logon CORP\\alice type 10 from 1.1.1.1"));
        assert!(is_logon_type_10("logon alice type 10"));
        assert!(!is_logon_type_10("logon alice type 3"));
        assert!(!is_logon_type_10("logon alice type 100"));
    }
}
