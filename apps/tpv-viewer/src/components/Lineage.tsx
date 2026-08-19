import { useMemo } from "react";
import type { ProcessNode } from "../api";
import { baseName, duration } from "../format";
import { processFields } from "../report";
import { useVirtual } from "../useVirtual";
import { flattenForest, type FlatRow } from "../tree";
import { ColumnHeader, cellStyle, useColumns, type ColumnSpec } from "./Columns";
import { useArtifactMenu } from "./ContextMenu";

const ROW_H = 22;

const COLUMNS: ColumnSpec[] = [
  { id: "start", label: "Started (UTC)", width: 210, min: 90 },
  { id: "delta", label: "After parent", width: 92, min: 56, align: "right" },
  { id: "process", label: "Process", width: 330, min: 140 },
  { id: "pid", label: "PID", width: 58, min: 40, align: "right" },
  { id: "user", label: "User", width: 140, min: 60 },
  { id: "cmdline", label: "Command line", width: 400, min: 120, flex: true },
];

/**
 * The process forest read as a timeline.
 *
 * The flat event list answers "what happened at 11:04", this answers "what did
 * that spawn". Both are chronological; the difference is that here a child sits
 * under its parent, so the shape of an intrusion — one document opening one
 * shell opening one downloader — is visible as a shape rather than something the
 * analyst has to reconstruct from adjacent rows.
 */
export function Lineage({
  roots,
  collapsed,
  onToggle,
  match,
  selected,
  onSelect,
}: {
  roots: ProcessNode[];
  collapsed: ReadonlySet<string>;
  onToggle: (key: string) => void;
  match?: (n: ProcessNode) => boolean;
  selected: string | null;
  onSelect: (n: ProcessNode) => void;
}) {
  const rows = useMemo(
    () => flattenForest(roots, collapsed, match),
    [roots, collapsed, match],
  );
  const v = useVirtual(rows.length, ROW_H);
  const menu = useArtifactMenu();
  const { widths, resize, reset } = useColumns("tpv.cols.lineage", COLUMNS);
  const style = useMemo(
    () => Object.fromEntries(COLUMNS.map((c) => [c.id, cellStyle(c, widths)])),
    [widths],
  );

  // Parent start times, so each row can show how long after its parent it ran.
  const parentStart = useMemo(() => {
    const m = new Map<string, number | null>();
    const walk = (n: ProcessNode) => {
      for (const c of n.children) {
        m.set(c.key, n.started?.ns ?? null);
        walk(c);
      }
    };
    for (const r of roots) walk(r);
    return m;
  }, [roots]);

  return (
    <div className="table">
      <ColumnHeader spec={COLUMNS} widths={widths} onResize={resize} onReset={reset} />
      {rows.length === 0 ? (
        <div className="events">
          <div className="muted">No process matches the current filter.</div>
        </div>
      ) : (
        <div className="events" ref={v.ref} onScroll={v.onScroll}>
          <div style={{ height: v.totalHeight, position: "relative" }}>
            <div style={{ transform: `translateY(${v.padTop}px)` }}>
              {rows.slice(v.first, v.last).map((row) => (
                <Row
                  key={row.node.key}
                  row={row}
                  style={style}
                  parentNs={parentStart.get(row.node.key) ?? null}
                  selected={selected === row.node.key}
                  onToggle={onToggle}
                  onSelect={onSelect}
                  onMenu={(e, n, field) => {
                    onSelect(n);
                    menu.openFields(e, processFields(n), field);
                  }}
                />
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Row({
  row,
  style,
  parentNs,
  selected,
  onToggle,
  onSelect,
  onMenu,
}: {
  row: FlatRow;
  style: Record<string, React.CSSProperties>;
  parentNs: number | null;
  selected: boolean;
  onToggle: (key: string) => void;
  onSelect: (n: ProcessNode) => void;
  onMenu: (e: React.MouseEvent, n: ProcessNode, field?: string) => void;
}) {
  const n = row.node;
  const started = n.started;
  const gap =
    started && parentNs !== null && started.ns >= parentNs
      ? duration(started.ns - parentNs)
      : "";

  return (
    <div
      className={`ev-row${selected ? " sel" : ""}${row.contextOnly ? " context" : ""}`}
      onClick={() => onSelect(n)}
      onContextMenu={(e) => {
        const field = (e.target as HTMLElement | null)?.closest?.("[data-field]")?.getAttribute("data-field") ?? undefined;
        onMenu(e, n, field ?? "Command line");
      }}
    >
      <span
        className={`cell mono${started && !started.exact ? " suspect" : ""}`}
        style={style.start}
        data-field={started?.exact === false ? "First seen" : "Started"}
        title={
          started?.exact === false
            ? "the creation time could not be read; this is when the process was first seen"
            : undefined
        }
      >
        {started ? started.iso : "\u2014"}
      </span>
      <span className="cell mono right dimmed" style={style.delta} title={gap ? "time between the parent starting and this process starting" : undefined}>
        {gap}
      </span>
      <span className="cell" style={style.process} data-field="Process">
        <span style={{ width: row.depth * 14, flex: "0 0 auto" }} />
        {row.hasChildren ? (
          <button
            className="twisty"
            onClick={(e) => {
              e.stopPropagation();
              onToggle(n.key);
            }}
          >
            {row.expanded ? "\u25be" : "\u25b8"}
          </button>
        ) : (
          <span className="twisty-gap" />
        )}
        <span className="proc-name" title={n.image ?? n.label}>
          {n.image ? baseName(n.image) : n.label}
        </span>
        {n.elevated && <span className="tree-flag" title="running elevated">{"\u2191"}</span>}
        {n.access_error && (
          <span className="tree-flag warn" title={n.access_error}>
            {"\u00d7"}
          </span>
        )}
      </span>
      <span className="cell mono right" style={style.pid} data-field="PID">
        {n.pid ?? ""}
      </span>
      <span className="cell dimmed" style={style.user} title={n.user ?? undefined} data-field="User">
        {n.user ?? ""}
      </span>
      <span className="cell mono" style={style.cmdline} title={n.command_line ?? undefined} data-field="Command line">
        {n.command_line ?? ""}
      </span>
    </div>
  );
}
