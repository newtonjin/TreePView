//! Filtered-view export: CSV, JSONL, and a one-page markdown brief.

use tpv_model::{Finding, ManifestEntry};

use crate::reader::{CaseMeta, Counts, EventRow};

/// CSV of the filtered event table. One header row, RFC 4180 quoting.
pub fn events_csv(rows: &[EventRow]) -> String {
    let mut out = String::from(
        "utc,source,kind,event_id,pid,ppid,image,user,path,remote,summary\n",
    );
    for r in rows {
        out.push_str(&csv_row(&[
            r.iso.as_str(),
            r.source.as_str(),
            r.kind.as_str(),
            &r.log_id.map(|n| n.to_string()).unwrap_or_default(),
            &r.pid.map(|n| n.to_string()).unwrap_or_default(),
            &r.ppid.map(|n| n.to_string()).unwrap_or_default(),
            r.image.as_deref().unwrap_or(""),
            r.user.as_deref().unwrap_or(""),
            r.path.as_deref().unwrap_or(""),
            r.remote.as_deref().unwrap_or(""),
            r.summary.as_str(),
        ]));
        out.push('\n');
    }
    out
}

/// One JSON object per line.
pub fn events_jsonl(rows: &[EventRow]) -> Result<String, serde_json::Error> {
    let mut out = String::new();
    for r in rows {
        out.push_str(&serde_json::to_string(r)?);
        out.push('\n');
    }
    Ok(out)
}

/// One-page markdown: host, custody, gaps, counts, then a sample of the view.
pub fn case_markdown(
    meta: &CaseMeta,
    counts: &Counts,
    manifest: &[ManifestEntry],
    findings: &[Finding],
    sample: &[EventRow],
    matching: i64,
) -> String {
    let mut md = String::new();
    md.push_str(&format!("# TreePView — {}\n\n", meta.host.hostname));
    md.push_str(&format!(
        "- **OS:** {} {} {}\n",
        meta.host.os_name, meta.host.os_version, meta.host.architecture
    ));
    md.push_str(&format!("- **Case:** `{}`\n", meta.case_id));
    md.push_str(&format!("- **Tool:** {}\n", meta.tool_version));
    md.push_str(&format!(
        "- **Finalized:** {}\n",
        if meta.finalized { "yes" } else { "no (partial)" }
    ));
    if let Some(d) = &meta.content_digest {
        md.push_str(&format!("- **Content SHA-256:** `{d}`\n"));
    }
    md.push_str(&format!(
        "- **Counts:** {} events, {} entities, {} findings\n",
        counts.events, counts.entities, counts.findings
    ));

    if let Some(c) = &meta.custody {
        md.push_str("\n## Custody\n\n");
        md.push_str(&format!(
            "- Ran as {} {}\n",
            c.run_as_user,
            if c.elevated {
                "(elevated)"
            } else {
                "(not elevated)"
            }
        ));
        md.push_str(&format!("- Command: `{}`\n", c.command_line));
        if !c.warnings.is_empty() {
            md.push_str("\nWarnings:\n");
            for w in &c.warnings {
                md.push_str(&format!("- {w}\n"));
            }
        }
    }

    let gaps: Vec<&ManifestEntry> = manifest.iter().filter(|m| m.error.is_some()).collect();
    if !gaps.is_empty() {
        md.push_str("\n## Gaps\n\n");
        for g in gaps {
            md.push_str(&format!(
                "- `{}`: {}\n",
                g.source_path,
                g.error.as_deref().unwrap_or("")
            ));
        }
    }

    if !findings.is_empty() {
        md.push_str("\n## Findings\n\n");
        for f in findings {
            md.push_str(&format!(
                "- **{}** ({}/{}): {}\n",
                f.title,
                f.severity.as_str(),
                f.confidence.as_str(),
                f.detail
            ));
        }
    }

    md.push_str(&format!(
        "\n## Events in this view ({matching} matching, showing {})\n\n",
        sample.len()
    ));
    for r in sample {
        md.push_str(&format!(
            "- `{}` [{} / {}] {}\n",
            r.iso, r.source, r.kind, r.summary
        ));
    }
    md.push('\n');
    md
}

fn csv_row(fields: &[&str]) -> String {
    fields.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(",")
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
