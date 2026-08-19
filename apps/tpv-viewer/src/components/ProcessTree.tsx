import { useMemo, useState } from "react";
import type { ProcessNode } from "../api";
import { processFields } from "../report";
import { useVirtual } from "../useVirtual";
import { useArtifactMenu } from "./ContextMenu";
import { branchKeys, countForest, flattenForest, textPredicate } from "../tree";

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
  onSelect,
  collapsed,
  onToggle,
  onSetCollapsed,
}: {
  roots: ProcessNode[];
  selected: string | null;
  onSelect: (node: ProcessNode | null) => void;
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
          placeholder="name, pid, user, path or command line"
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
            {rows.slice(v.first, v.last).map(({ node, depth, hasChildren, expanded, contextOnly }) => (
              <div
                key={node.key}
                className={`tree-row${selected === node.key ? " sel" : ""}${
                  contextOnly ? " context" : ""
                }`}
                style={{ paddingLeft: 4 + depth * 13 }}
                onClick={() => onSelect(selected === node.key ? null : node)}
                onContextMenu={(e) => {
                  onSelect(node);
                  menu.openFields(e, processFields(node), preferredField(e.target, detail));
                }}
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
                <Detail node={node} kind={detail} />
              </div>
            ))}
          </div>
        </div>
        {rows.length === 0 && <div className="muted">No process matches.</div>}
      </div>

      <div className="pane-foot">
        {rows.length.toLocaleString()} shown of {totalProcs.toLocaleString()}
      </div>
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
  return lines.join("\n");
}
