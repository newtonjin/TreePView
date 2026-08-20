import { useMemo, useState } from "react";
import type { ProcessNode } from "../api";
import { processFields } from "../report";
import { useVirtual } from "../useVirtual";
import { useArtifactMenu } from "./ContextMenu";
import { branchKeys, countForest, edgeCounts, flattenForest, textPredicate, type FlatRow } from "../tree";

const ROW_H = 22;

/** What the row shows next to the process name. */
type Detail = "none" | "user" | "cmdline" | "image";

const DETAILS: { id: Detail; label: string }[] = [
  { id: "none", label: "count" },
  { id: "user", label: "user" },
  { id: "cmdline", label: "command line" },
  { id: "image", label: "path" },
];

export function ProcessTree({
  roots,
  selected,
  selectedEventId,
  onSelect,
  collapsed,
  onToggle,
  onSetCollapsed,
}: {
  roots: ProcessNode[];
  selected: string | null;
  selectedEventId: number | null;
  onSelect: (node: ProcessNode | null, logEventId?: number) => void;
  collapsed: ReadonlySet<string>;
  onToggle: (key: string) => void;
  onSetCollapsed: (keys: Set<string>) => void;
}) {
  const [needle, setNeedle] = useState("");
  const [detail, setDetail] = useState<Detail>("none");
  const menu = useArtifactMenu();

  // Searching the command line matters more than searching the name: a renamed
  // binary keeps its arguments, and the arguments are where a C2 URL or an
  // encoded PowerShell payload actually lives.
  const rows = useMemo(
    () => flattenForest(roots, collapsed, textPredicate(needle)),
    [roots, collapsed, needle],
  );
  const totalProcs = useMemo(() => countForest(roots), [roots]);
  const edges = useMemo(() => edgeCounts(roots), [roots]);
  const logShown = useMemo(() => rows.filter((r) => r.log).length, [rows]);
  const procShown = rows.length - logShown;

  const v = useVirtual(rows.length, ROW_H);

  return (
    <div className="pane">
      <div className="pane-head">
        <span>Processes</span>
        <span className="spacer" />
        <button onClick={() => onSetCollapsed(new Set())}>Expand</button>
        <button onClick={() => onSetCollapsed(new Set(branchKeys(roots)))}>Collapse</button>
      </div>

      <div className="tree-controls">
        <input
          type="search"
          placeholder="name, pid, Event ID, path or command line"
          value={needle}
          onChange={(e) => setNeedle(e.target.value)}
        />
        <div className="chipset">
          <span className="tiny-label">show</span>
          {DETAILS.map((d) => (
            <span
              key={d.id}
              className={`chip${detail === d.id ? " on" : ""}`}
              onClick={() => setDetail(d.id)}
            >
              {d.label}
            </span>
          ))}
        </div>
      </div>

      <div className="pane-body" ref={v.ref} onScroll={v.onScroll}>
        <div style={{ height: v.totalHeight, position: "relative" }}>
          <div style={{ transform: `translateY(${v.padTop}px)` }}>
            {rows.slice(v.first, v.last).map((row) => (
              <TreeRow
                key={rowKey(row)}
                row={row}
                detail={detail}
                selected={
                  row.log
                    ? selectedEventId === row.log.event_id
                    : selected === row.node.key && selectedEventId == null
                }
                onToggle={onToggle}
                onSelect={onSelect}
                onMenu={(e, n) => {
                  onSelect(n);
                  menu.openFields(e, processFields(n), preferredField(e.target, detail));
                }}
              />
            ))}
          </div>
        </div>
        {rows.length === 0 && <div className="muted">No process matches.</div>}
      </div>

      <div className="pane-foot">
        {procShown.toLocaleString()} shown of {totalProcs.toLocaleString()}
        {logShown > 0 ? ` · ${logShown.toLocaleString()} Event IDs` : ""}
        {" · "}
        {edges.confirmed} confirmed / {edges.inferred} inferred / {edges.orphaned} orphaned
        {edges.impossible > 0 ? ` / ${edges.impossible} recycled` : ""}
      </div>
    </div>
  );
}

function rowKey(row: FlatRow): string {
  return row.log ? `${row.node.key}:log:${row.log.event_id}` : row.node.key;
}

function TreeRow({
  row,
  detail,
  selected,
  onToggle,
  onSelect,
  onMenu,
}: {
  row: FlatRow;
  detail: Detail;
  selected: boolean;
  onToggle: (key: string) => void;
  onSelect: (node: ProcessNode | null, logEventId?: number) => void;
  onMenu: (e: React.MouseEvent, n: ProcessNode) => void;
}) {
  const { node, depth, hasChildren, expanded, contextOnly, log } = row;

  if (log) {
    const eid = log.log_id != null ? String(log.log_id) : "—";
    return (
      <div
        className={`tree-row log${selected ? " sel" : ""}`}
        style={{ paddingLeft: 4 + depth * 13 }}
        onClick={() => onSelect(node, log.event_id)}
        title={`${eid} · ${log.kind} · ${log.source}\n${log.summary}`}
      >
        <span className="twisty" />
        <span className="tree-eid">{eid}</span>
        <span className="tree-label">{log.summary}</span>
      </div>
    );
  }

  const logN = node.related_logs?.length ?? 0;
  const omitted = node.related_logs_omitted ?? 0;

  return (
    <div
      className={`tree-row${selected ? " sel" : ""}${contextOnly ? " context" : ""} ${node.parent_edge}`}
      style={{ paddingLeft: 4 + depth * 13 }}
      onClick={() => onSelect(selected ? null : node)}
      onContextMenu={(e) => onMenu(e, node)}
      title={tooltip(node)}
    >
      <span
        className="twisty"
        onClick={(e) => {
          e.stopPropagation();
          if (hasChildren) onToggle(node.key);
        }}
      >
        {hasChildren ? (expanded ? "\u25bc" : "\u25b6") : ""}
      </span>
      {node.max_severity && <span className={`dot ${node.max_severity}`} />}
      <span className="tree-label" data-field="Process">
        {node.label}
      </span>
      <span className="tree-pid" data-field="PID">
        {node.pid ?? "?"}
      </span>
      {node.elevated && (
        <span className="tree-flag" title="running elevated">
          {"\u2191"}
        </span>
      )}
      {node.access_error && (
        <span className="tree-flag denied" title={node.access_error}>
          {"\u00d7"}
        </span>
      )}
      {node.indicators.length > 0 && (
        <span className="tree-flag warn" title={node.indicators.join("\n")}>
          !
        </span>
      )}
      {node.parent_edge === "orphaned" && (
        <span className="tree-flag orphan" title={`parent PID ${node.claimed_ppid ?? "?"} not in this case`}>
          orphan
        </span>
      )}
      {node.parent_edge === "impossible" && (
        <span
          className="tree-flag orphan"
          title={`parent PID ${node.claimed_ppid ?? "?"} not resolvable — recycled PID`}
        >
          recycled
        </span>
      )}
      {logN > 0 && (
        <span
          className="tree-flag logs"
          title={`${logN + omitted} correlated Event Log row${logN + omitted === 1 ? "" : "s"} on this branch`}
        >
          {logN}
          {omitted > 0 ? `+${omitted}` : ""}
        </span>
      )}
      <Detail node={node} kind={detail} />
    </div>
  );
}

function Detail({ node, kind }: { node: ProcessNode; kind: Detail }) {
  if (kind === "none") return <span className="tree-count">{node.event_count}</span>;

  const field = kind === "user" ? "User" : kind === "cmdline" ? "Command line" : "Image";
  const value =
    kind === "user" ? node.user : kind === "cmdline" ? node.command_line : node.image;

  // A denied process is not a process without a command line, and the row has to
  // say which it is or the analyst will read the blank as a fact.
  if (!value) {
    return (
      <span className="tree-detail empty">
        {node.access_error ? "access denied" : "\u2014"}
      </span>
    );
  }
  return (
    <span className="tree-detail" data-field={field}>
      {value}
    </span>
  );
}

function preferredField(target: EventTarget, detail: Detail): string {
  const tagged = (target as HTMLElement | null)?.closest?.("[data-field]");
  const fromDom = tagged?.getAttribute("data-field");
  if (fromDom) return fromDom;
  if (detail === "cmdline") return "Command line";
  if (detail === "image") return "Image";
  if (detail === "user") return "User";
  return "Command line";
}

function tooltip(n: ProcessNode): string {
  const lines = [n.image ?? n.label];
  if (n.command_line) lines.push(n.command_line);
  if (n.user) lines.push(`user: ${n.user}${n.elevated ? " (elevated)" : ""}`);
  if (n.started) {
    lines.push(
      n.started.exact
        ? `started: ${n.started.iso}`
        : `first seen: ${n.started.iso} (creation time unreadable)`,
    );
  }
  if (n.access_error) lines.push(`not inspected: ${n.access_error}`);
  if (n.source_set.length) lines.push(`sources: ${n.source_set.join(", ")}`);
  if (n.parent_edge === "inferred") lines.push("parent inferred (start/exit unknown)");
  if (n.parent_edge === "orphaned") {
    lines.push(`parent PID ${n.claimed_ppid ?? "?"} not in this case`);
  }
  if (n.parent_edge === "impossible") {
    lines.push(`parent PID ${n.claimed_ppid ?? "?"} not resolvable — recycled PID`);
  }
  if (n.indicators.length) lines.push(n.indicators.join(", "));
  const logs = n.related_logs ?? [];
  if (logs.length) {
    lines.push(
      `event logs: ${logs
        .slice(0, 8)
        .map((l) => l.log_id ?? l.kind)
        .join(", ")}${n.related_logs_omitted ? ` (+${n.related_logs_omitted} more)` : ""}`,
    );
  }
  return lines.join("\n");
}
