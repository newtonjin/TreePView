import { useEffect, useMemo } from "react";
import type { EventFilter, EventRow } from "../api";
import { baseName, isSuspect } from "../format";
import { eventFields } from "../report";
import { useVirtual } from "../useVirtual";
import { ColumnHeader, cellStyle, useColumns, type ColumnSpec } from "./Columns";
import { useArtifactMenu, type MenuItem } from "./ContextMenu";

const ROW_H = 22;

const EVENT_COLUMNS: ColumnSpec[] = [
  { id: "time", label: "Time (UTC)", width: 210, min: 90 },
  { id: "source", label: "Source", width: 70, min: 44 },
  { id: "kind", label: "Kind", width: 120, min: 60 },
  { id: "eid", label: "Event ID", width: 72, min: 48, align: "right" },
  { id: "process", label: "Process", width: 140, min: 60 },
  { id: "pid", label: "PID", width: 58, min: 40, align: "right" },
  { id: "summary", label: "Summary", width: 400, min: 120, flex: true },
  { id: "remote", label: "Remote", width: 170, min: 60 },
];

const LOG_COLUMNS: ColumnSpec[] = [
  { id: "time", label: "Time (UTC)", width: 210, min: 90 },
  { id: "source", label: "Source", width: 64, min: 44 },
  { id: "kind", label: "Kind", width: 110, min: 60 },
  { id: "eid", label: "Event ID", width: 72, min: 48, align: "right" },
  { id: "channel", label: "Channel", width: 140, min: 60 },
  { id: "process", label: "Process", width: 120, min: 60 },
  { id: "pid", label: "PID", width: 58, min: 40, align: "right" },
  { id: "user", label: "User", width: 130, min: 60 },
  { id: "summary", label: "Summary", width: 360, min: 120, flex: true },
];

export function EventTable({
  rows,
  total,
  loading,
  selected,
  mode,
  filter,
  onSelect,
  onLoadMore,
  onFilter,
  onPin,
}: {
  rows: EventRow[];
  total: number;
  loading: boolean;
  selected: number | null;
  mode: "events" | "logs";
  filter: EventFilter;
  onSelect: (row: EventRow) => void;
  onLoadMore: () => void;
  onFilter: (f: EventFilter) => void;
  onPin: (entityKey: string | null, pid: number | null) => void;
}) {
  const columns = mode === "logs" ? LOG_COLUMNS : EVENT_COLUMNS;
  const v = useVirtual(rows.length, ROW_H);
  const menu = useArtifactMenu();
  const { widths, resize, reset } = useColumns(
    mode === "logs" ? "tpv.cols.logs" : "tpv.cols.events",
    columns,
  );
  const style = useMemo(
    () => Object.fromEntries(columns.map((c) => [c.id, cellStyle(c, widths)])),
    [columns, widths],
  );
  const colFilters = columnValues(filter);

  useEffect(() => {
    if (!loading && rows.length < total && v.last > rows.length - 60) onLoadMore();
  }, [v.last, rows.length, total, loading, onLoadMore]);

  const empty =
    mode === "logs"
      ? "No event-log record matches the current filter."
      : "No event matches the current filter.";

  return (
    <div className="table">
      <ColumnHeader
        spec={columns}
        widths={widths}
        onResize={resize}
        onReset={reset}
        filters={colFilters}
        onFilter={(id, value) => onFilter(setColumn(filter, id, value))}
      />
      {rows.length === 0 ? (
        <div className="events">
          <div className="muted">{loading ? "Querying\u2026" : empty}</div>
        </div>
      ) : (
        <div className="events" ref={v.ref} onScroll={v.onScroll}>
          <div style={{ height: v.totalHeight, position: "relative" }}>
            <div style={{ transform: `translateY(${v.padTop}px)` }}>
              {rows.slice(v.first, v.last).map((r) => (
                <div
                  key={r.id}
                  className={`ev-row${selected === r.id ? " sel" : ""}`}
                  onClick={() => onSelect(r)}
                  onContextMenu={(e) => {
                    onSelect(r);
                    const field =
                      (e.target as HTMLElement | null)
                        ?.closest?.("[data-field]")
                        ?.getAttribute("data-field") ?? "Summary";
                    menu.openFields(e, eventFields(r), field, rowActions(r, field, filter, onFilter, onPin));
                  }}
                >
                  <span
                    className={`cell mono${isSuspect(r.ts) ? " suspect" : ""}`}
                    style={style.time}
                    data-field="Time (UTC)"
                    title={
                      isSuspect(r.ts)
                        ? "this timestamp is inferred or was never recorded"
                        : undefined
                    }
                  >
                    {r.iso}
                  </span>
                  <span className="cell dimmed" style={style.source} data-field="Source">
                    {r.source}
                  </span>
                  <span className="cell dimmed" style={style.kind} data-field="Kind">
                    {r.kind}
                  </span>
                  <span className="cell mono right" style={style.eid} data-field="Event ID">
                    {r.log_id ?? ""}
                  </span>
                  {mode === "logs" && (
                    <span className="cell dimmed" style={style.channel} title={r.path ?? undefined} data-field="Channel">
                      {r.path ?? ""}
                    </span>
                  )}
                  <span className="cell" style={style.process} title={r.image ?? undefined} data-field="Process">
                    {r.image ? baseName(r.image) : ""}
                  </span>
                  <span className="cell mono right" style={style.pid} data-field="PID">
                    {r.pid ?? ""}
                  </span>
                  {mode === "logs" && (
                    <span className="cell" style={style.user} data-field="User">
                      {r.user ?? ""}
                    </span>
                  )}
                  <span className="cell" style={style.summary} title={r.summary} data-field="Summary">
                    {r.summary}
                  </span>
                  {mode === "events" && (
                    <span className="cell mono" style={style.remote} title={r.remote ?? undefined} data-field="Remote">
                      {r.remote ?? ""}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
      <div className="pane-foot">
        {rows.length.toLocaleString()} loaded of {total.toLocaleString()}
        {loading ? " \u2014 loading\u2026" : ""}
        {rows.length < total ? " \u2014 scroll for more" : ""}
      </div>
    </div>
  );
}

function columnValues(f: EventFilter): Record<string, string> {
  return {
    source: f.sourceContains ?? "",
    kind: f.kindContains ?? "",
    process: f.imageContains ?? "",
    pid: f.pidContains ?? (f.pids?.length === 1 ? String(f.pids[0]) : ""),
    eid: f.logIdContains ?? (f.logIds?.length === 1 ? String(f.logIds[0]) : ""),
    summary: f.summaryContains ?? "",
    remote: f.remoteContains ?? "",
    channel: f.pathContains ?? "",
    user: f.userContains ?? "",
  };
}

function setColumn(f: EventFilter, id: string, value: string): EventFilter {
  const v = value.trim() ? value : null;
  switch (id) {
    case "source":
      return { ...f, sourceContains: v };
    case "kind":
      return { ...f, kindContains: v };
    case "process":
      return { ...f, imageContains: v };
    case "pid":
      return { ...f, pidContains: v, pids: [] };
    case "eid":
      return { ...f, logIdContains: v, logIds: [] };
    case "summary":
      return { ...f, summaryContains: v };
    case "remote":
      return { ...f, remoteContains: v };
    case "channel":
      return { ...f, pathContains: v };
    case "user":
      return { ...f, userContains: v };
    default:
      return f;
  }
}

function rowActions(
  r: EventRow,
  field: string,
  filter: EventFilter,
  onFilter: (f: EventFilter) => void,
  onPin: (entityKey: string | null, pid: number | null) => void,
): MenuItem[] {
  const items: MenuItem[] = [];
  const fieldValue = valueForField(r, field);
  if (fieldValue && field !== "Time (UTC)") {
    items.push({
      label: `Filter to this ${field.toLowerCase()}`,
      action: () => onFilter(applyFieldFilter(filter, field, r)),
    });
  }
  items.push({
    label: `Only ${r.kind.replace(/_/g, " ")}`,
    action: () => onFilter({ ...filter, kinds: [r.kind], kindContains: null }),
  });
  if (r.source === "evtx" || r.source === "journald" || r.source === "auditd") {
    items.push({
      label: "Only event logs",
      action: () => onFilter({ ...filter, logsOnly: true, sources: [], networkOnly: false }),
    });
  }
  if (r.entity_key || r.pid != null) {
    items.push({
      label: r.pid != null ? `Pin PID ${r.pid} in the tree` : "Pin process in the tree",
      action: () => onPin(r.entity_key, r.pid),
    });
  }
  return items;
}

function valueForField(r: EventRow, field: string): string {
  switch (field) {
    case "Source":
      return r.source;
    case "Kind":
      return r.kind;
    case "Process":
      return r.image ?? "";
    case "PID":
      return r.pid != null ? String(r.pid) : "";
    case "Event ID":
      return r.log_id != null ? String(r.log_id) : "";
    case "Summary":
      return r.summary;
    case "Remote":
      return r.remote ?? "";
    case "Channel":
    case "Path":
      return r.path ?? "";
    case "User":
      return r.user ?? "";
    default:
      return "";
  }
}

function applyFieldFilter(f: EventFilter, field: string, r: EventRow): EventFilter {
  switch (field) {
    case "Source":
      return { ...f, sources: [r.source], sourceContains: null };
    case "Kind":
      return { ...f, kinds: [r.kind], kindContains: null };
    case "Process":
      return { ...f, imageContains: r.image };
    case "PID":
      return { ...f, pids: r.pid != null ? [r.pid] : [], pidContains: null };
    case "Event ID":
      return {
        ...f,
        logIds: r.log_id != null ? [r.log_id] : [],
        logIdContains: null,
      };
    case "Summary":
      return { ...f, summaryContains: r.summary };
    case "Remote":
      return { ...f, remoteContains: r.remote };
    case "Channel":
    case "Path":
      return { ...f, pathContains: r.path };
    case "User":
      return { ...f, userContains: r.user };
    default:
      return f;
  }
}
