/**
 * Labeled text ready to paste into an incident report.
 *
 * One field per line, `Label: value`, so the block survives Word, markdown and
 * a ticket comment without depending on a table renderer.
 */
import type { CaseOverview, EventRow, Finding, ProcessNode } from "./api";

export interface ReportField {
  label: string;
  value: string;
}

export function processFields(n: ProcessNode): ReportField[] {
  const fields: ReportField[] = [
    { label: "Process", value: n.label },
  ];
  if (n.pid != null) fields.push({ label: "PID", value: String(n.pid) });
  if (n.user) {
    fields.push({
      label: "User",
      value: n.elevated ? `${n.user} (elevated)` : n.user,
    });
  }
  if (n.image) fields.push({ label: "Image", value: n.image });
  if (n.command_line) fields.push({ label: "Command line", value: n.command_line });
  if (n.started) {
    fields.push({
      label: n.started.exact ? "Started" : "First seen",
      value: n.started.iso,
    });
  }
  if (n.access_error) fields.push({ label: "Not inspected", value: n.access_error });
  return fields;
}

export function eventFields(r: EventRow): ReportField[] {
  const fields: ReportField[] = [
    { label: "Time (UTC)", value: r.iso },
    { label: "Source", value: r.source },
    { label: "Kind", value: r.kind },
  ];
  if (r.image) fields.push({ label: "Process", value: r.image });
  if (r.pid != null) fields.push({ label: "PID", value: String(r.pid) });
  if (r.ppid != null) fields.push({ label: "Parent PID", value: String(r.ppid) });
  if (r.log_id != null) fields.push({ label: "Event ID", value: String(r.log_id) });
  if (r.user) fields.push({ label: "User", value: r.user });
  if (r.path) fields.push({ label: r.source === "evtx" ? "Channel" : "Path", value: r.path });
  if (r.remote) fields.push({ label: "Remote", value: r.remote });
  if (r.summary) fields.push({ label: "Summary", value: r.summary });
  return fields;
}

/** `Label: value` lines, trailing newline so sequential pastes stay separated. */
export function formatFields(fields: ReportField[]): string {
  return fields
    .filter((f) => f.value.length > 0)
    .map((f) => `${f.label}: ${f.value}`)
    .join("\n") + "\n";
}

/** One-page markdown brief from the case overview (host, custody, gaps, counts). */
export function caseBriefMarkdown(o: CaseOverview, findings: Finding[] = []): string {
  const h = o.meta.host;
  const c = o.meta.custody;
  const lines: string[] = [
    `# TreePView — ${h.hostname}`,
    "",
    `- **OS:** ${h.os_name} ${h.os_version} ${h.architecture}`,
    `- **Events:** ${o.counts.events}`,
    `- **Entities:** ${o.counts.entities}`,
    `- **Findings:** ${findings.length}`,
    `- **Finalized:** ${o.meta.finalized ? "yes" : "no (partial)"}`,
  ];
  if (o.meta.content_digest) {
    lines.push(`- **Content SHA-256:** \`${o.meta.content_digest}\``);
  }
  if (c) {
    lines.push("", "## Custody", "");
    lines.push(`- Ran as ${c.run_as_user} ${c.elevated ? "(elevated)" : "(not elevated)"}`);
    lines.push(`- Command: \`${c.command_line}\``);
    for (const w of c.warnings) lines.push(`- ${w}`);
  }
  if (o.gaps.length > 0) {
    lines.push("", "## Gaps", "");
    for (const g of o.gaps) lines.push(`- \`${g.sourcePath}\`: ${g.error}`);
  }
  if (findings.length > 0) {
    lines.push("", "## Findings", "");
    for (const f of findings) {
      lines.push(`- **${f.title}** (${f.severity}): ${f.detail}`);
    }
  }
  return lines.join("\n") + "\n";
}

export function selectionText(): string {
  return window.getSelection()?.toString() ?? "";
}

export async function copyText(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const el = document.createElement("textarea");
    el.value = text;
    el.setAttribute("readonly", "");
    el.style.position = "fixed";
    el.style.left = "-9999px";
    document.body.appendChild(el);
    el.select();
    document.execCommand("copy");
    document.body.removeChild(el);
  }
}
