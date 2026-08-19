import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import {
  openCase,
  overview as fetchOverview,
  processTree,
  paddedWindow,
  isFullSpan,
  queryEvents,
  verify,
  findings as fetchFindings,
  manifest as fetchManifest,
  exportEvents,
  type CaseOverview,
  type EventFilter,
  type EventRow,
  type Finding,
  type ManifestEntry,
  type ProcessNode,
  type VerifyReport,
} from "./api";
import { FilterBar } from "./components/FilterBar";
import { EventTable } from "./components/EventTable";
import { Inspector, type Target } from "./components/Inspector";
import { Lineage } from "./components/Lineage";
import { ProcessTree } from "./components/ProcessTree";
import { Splitter, usePersistentNumber } from "./components/Splitter";
import { Timeline, type Mark } from "./components/Timeline";
import { andPredicates, findNode, findNodeByPid, rangePredicate, textPredicate } from "./tree";

const PAGE = 500;

const OPEN_FILTERS = [
  { name: "TreePView case", extensions: ["tpv"] },
  { name: "Memory image", extensions: ["raw", "dmp", "dump", "mem", "vmem", "lime", "dd", "bin", "core"] },
  { name: "All files", extensions: ["*"] },
];

type CenterView = "events" | "lineage" | "logs";

export default function App() {
  const [caseInfo, setCase] = useState<CaseOverview | null>(null);
  const [tree, setTree] = useState<ProcessNode[]>([]);
  const [integrity, setIntegrity] = useState<VerifyReport | null>(null);
  const [findingsList, setFindings] = useState<Finding[]>([]);
  const [manifestRows, setManifest] = useState<ManifestEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [filter, setFilter] = useState<EventFilter>({});
  const [view, setView] = useState<[number, number] | null>(null);
  const [focusedEntity, setFocusedEntity] = useState<string | null>(null);
  const [target, setTarget] = useState<Target>({ kind: "case" });

  const [rows, setRows] = useState<EventRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);

  const [center, setCenter] = useState<CenterView>("events");
  // One collapse state for one hierarchy: the tree on the left and the lineage
  // in the middle are the same forest seen two ways, and letting them disagree
  // about which branches are open would make each one lie about the other.
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  const [leftW, setLeftW] = usePersistentNumber("tpv.pane.left", 300, 180, 900);
  const [rightW, setRightW] = usePersistentNumber("tpv.pane.right", 360, 220, 1000);

  const toggleNode = useCallback((key: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  // A case may already be open when the window appears, because the backend
  // opens a path handed to it on the command line.
  useEffect(() => {
    fetchOverview()
      .then((o) => adopt(o))
      .catch(() => {});
  }, []);

  const adopt = useCallback(async (o: CaseOverview) => {
    setCase(o);
    setError(null);
    setFilter({});
    setFocusedEntity(null);
    setTarget({ kind: "case" });
    setView(o.span);
    setTree(await processTree());
    setIntegrity(await verify());
    try {
      setFindings(await fetchFindings());
    } catch {
      setFindings([]);
    }
    try {
      setManifest(await fetchManifest());
    } catch {
      setManifest([]);
    }
  }, []);

  const pick = async () => {
    const path = await openDialog({
      multiple: false,
      filters: OPEN_FILTERS,
    });
    if (typeof path !== "string") return;
    setBusy(true);
    try {
      adopt(await openCase(path));
    } catch (e) {
      setError(String(e));
      setCase(null);
    } finally {
      setBusy(false);
    }
  };

  /**
   * The filter the backend actually receives.
   *
   * Time bounds come from the timeline viewport and the process constraint from
   * the tree selection, so the three panels stay one query rather than three
   * views that can disagree with each other.
   */
  const effective = useMemo<EventFilter>(() => {
    const span = caseInfo?.span ?? null;
    const window = isFullSpan(view, span) ? { fromNs: null, toNs: null } : paddedWindow(view);
    const base: EventFilter = {
      ...filter,
      fromNs: window.fromNs,
      toNs: window.toNs,
      entityKey: focusedEntity,
    };
    if (center === "logs") {
      return { ...base, logsOnly: true, networkOnly: false, sources: [] };
    }
    return base;
  }, [filter, view, focusedEntity, caseInfo?.span, center]);

  // Only the non-time part of the filter drives the histogram, otherwise zooming
  // would refetch a histogram that is by construction full across its own range.
  const histogramFilter = useMemo<EventFilter>(() => {
    const base: EventFilter = { ...filter, entityKey: focusedEntity };
    if (center === "logs") {
      return { ...base, logsOnly: true, networkOnly: false, sources: [] };
    }
    return base;
  }, [filter, focusedEntity, center]);

  // Resolved from the tree when possible so the chip reads "brave.exe" rather
  // than "proc:4980:1787...".
  const focusLabel = useMemo(() => {
    if (!focusedEntity) return null;
    const found = findNode(tree, focusedEntity);
    return found ? `${found.label} (pid ${found.pid ?? "?"})` : focusedEntity;
  }, [focusedEntity, tree]);

  /**
   * The lineage view is filtered here rather than by another backend query.
   *
   * The whole forest is a few hundred to a few thousand nodes and already in
   * memory, so filtering it locally is instant and, more importantly, keeps
   * ancestors visible: a server-side time filter would return the matching
   * processes without the parents that explain them.
   */
  const lineageMatch = useMemo(() => {
    const ps = [textPredicate(filter.text ?? "")];
    const span = caseInfo?.span ?? null;
    if (!isFullSpan(view, span)) {
      const window = paddedWindow(view);
      if (window.fromNs != null && window.toNs != null) {
        ps.push(rangePredicate(window.fromNs, window.toNs));
      }
    }
    return andPredicates(...ps);
  }, [filter.text, view, caseInfo?.span]);

  const logCount = useMemo(
    () =>
      (caseInfo?.sources ?? [])
        .filter((s) => s.value === "evtx" || s.value === "journald" || s.value === "auditd")
        .reduce((n, s) => n + s.count, 0),
    [caseInfo],
  );

  const marks = useMemo<Mark[]>(() => {
    const c = caseInfo?.meta.custody;
    return c ? [{ ns: c.started.utc_ns, label: "collected" }] : [];
  }, [caseInfo]);

  const generation = useRef(0);

  useEffect(() => {
    if (!caseInfo) return;
    const gen = ++generation.current;
    setLoading(true);
    // Debounced because the search box fires per keystroke and each keystroke
    // would otherwise start a full-text query over the whole case.
    const t = setTimeout(() => {
      queryEvents(effective, PAGE, 0)
        .then((page) => {
          if (gen !== generation.current) return;
          setRows(page.rows);
          setTotal(page.total);
        })
        .catch((e) => gen === generation.current && setError(String(e)))
        .finally(() => gen === generation.current && setLoading(false));
    }, 140);
    return () => clearTimeout(t);
  }, [caseInfo, effective]);

  const loadMore = useCallback(() => {
    if (loading || rows.length >= total) return;
    const gen = generation.current;
    setLoading(true);
    queryEvents(effective, PAGE, rows.length)
      .then((page) => {
        // Discard a page that arrives after the filter moved on, or it would
        // splice rows from the old query into the new result.
        if (gen !== generation.current) return;
        setRows((prev) => [...prev, ...page.rows]);
        setTotal(page.total);
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, [effective, loading, rows.length, total]);

  if (!caseInfo) {
    return (
      <div className="empty">
        <h1>
          Tree<span>P</span>View
        </h1>
        <p>
          Open a <code>.tpv</code> case, a memory image (<code>.raw</code>, crash dump, LiME,
          ELF core — Windows or Linux), or another recognised capture. Cases open read-only; a memory image is
          analysed on this machine and is never modified.
        </p>
        <button className="primary" onClick={pick} disabled={busy}>
          {busy ? "Opening\u2026" : "Open\u2026"}
        </button>
        {error && <div className="err">{error}</div>}
      </div>
    );
  }

  const host = caseInfo.meta.host;
  const interrupted = Boolean(
    caseInfo.meta.custody?.warnings.some((w) => w.includes("interrupted by operator")),
  );

  const exportView = async (format: "csv" | "jsonl" | "md") => {
    const ext = format === "md" ? "md" : format;
    const path = await saveDialog({
      defaultPath: `${host.hostname}.${ext}`,
      filters: [{ name: format.toUpperCase(), extensions: [ext] }],
    });
    if (typeof path !== "string") return;
    try {
      await exportEvents(path, format, effective);
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <div className="app">
      <div className="titlebar">
        <span className="brand">
          Tree<span>P</span>View
        </span>
        <span className="host">
          <b>{host.hostname}</b> {host.os_name} {host.os_version} {host.architecture}
        </span>

        <span className="spacer" />

        {!caseInfo.meta.finalized && (
          <span className="badge warn" title="The collector did not finish; absences may not be real">
            partial case
          </span>
        )}
        {interrupted && caseInfo.meta.finalized && (
          <span
            className="badge warn"
            title="Collection was interrupted and then sealed; verify still works"
          >
            interrupted (sealed)
          </span>
        )}
        {findingsList.length > 0 && (
          <span className="badge" title="Local regenerable findings">
            {findingsList.length} finding{findingsList.length === 1 ? "" : "s"}
          </span>
        )}
        {caseInfo.gaps.length > 0 && (
          <span className="badge warn" title="Some artifacts failed to acquire">
            {caseInfo.gaps.length} gap{caseInfo.gaps.length > 1 ? "s" : ""}
          </span>
        )}
        {integrity && (
          <span
            className={`badge ${integrity.digestMatches ? "ok" : "bad"}`}
            title={integrity.sealedDigest ?? "no digest was sealed"}
          >
            {integrity.digestMatches ? "integrity verified" : "integrity FAILED"}
          </span>
        )}
        <button onClick={() => void exportView("csv")} title="Export the current filter as CSV">
          CSV
        </button>
        <button onClick={() => void exportView("jsonl")} title="Export the current filter as JSONL">
          JSONL
        </button>
        <button onClick={() => void exportView("md")} title="One-page markdown brief">
          Report
        </button>
        <button onClick={pick} disabled={busy}>
          {busy ? "Opening\u2026" : "Open\u2026"}
        </button>
      </div>

      <FilterBar
        filter={filter}
        setFilter={setFilter}
        sources={caseInfo.sources}
        kinds={caseInfo.kinds}
        total={caseInfo.counts.events}
        matching={total}
        focus={focusLabel}
        onClearFocus={() => setFocusedEntity(null)}
        onReset={() => {
          setFilter({});
          setFocusedEntity(null);
          setView(caseInfo.span);
        }}
      />

      <div
        className="panes"
        style={{ gridTemplateColumns: `${leftW}px 5px 1fr 5px ${rightW}px` }}
      >
        <ProcessTree
          roots={tree}
          selected={focusedEntity}
          collapsed={collapsed}
          onToggle={toggleNode}
          onSetCollapsed={setCollapsed}
          onSelect={(node) => {
            setFocusedEntity(node?.key ?? null);
            if (node) setTarget({ kind: "entity", key: node.key });
          }}
        />

        <Splitter onDelta={(dx) => setLeftW((w) => w + dx)} onReset={() => setLeftW(300)} />

        <div className="pane center">
          {caseInfo.span && view ? (
            <Timeline
              filter={histogramFilter}
              span={caseInfo.span}
              view={view}
              marks={marks}
              onView={setView}
            />
          ) : (
            <div className="muted">
              No event in this case carries a usable timestamp, so there is no timeline to
              draw.
            </div>
          )}

          <div className="view-tabs">
            <span
              className={`tab${center === "events" ? " on" : ""}`}
              onClick={() => setCenter("events")}
            >
              Events
              <span className="tab-n">{center === "events" ? total.toLocaleString() : caseInfo.counts.events.toLocaleString()}</span>
            </span>
            <span
              className={`tab${center === "logs" ? " on" : ""}`}
              onClick={() => setCenter("logs")}
              title="Windows event logs and Linux journal/audit records"
            >
              Logs
              <span className="tab-n">{logCount.toLocaleString()}</span>
            </span>
            <span
              className={`tab${center === "lineage" ? " on" : ""}`}
              onClick={() => setCenter("lineage")}
              title="processes nested under whatever spawned them, in the order they started"
            >
              Lineage
            </span>
            <span className="spacer" />
            {center === "lineage" && (
              <span className="hint">
                nested under the parent that spawned them, oldest first
              </span>
            )}
            {center === "logs" && (
              <span className="hint">
                column filters and right-click actions apply to the log view
              </span>
            )}
          </div>

          {center === "lineage" ? (
            <Lineage
              roots={tree}
              collapsed={collapsed}
              onToggle={toggleNode}
              match={lineageMatch}
              selected={focusedEntity}
              onSelect={(n) => {
                setFocusedEntity(n.key);
                setTarget({ kind: "entity", key: n.key });
              }}
            />
          ) : (
            <EventTable
              key={center}
              mode={center === "logs" ? "logs" : "events"}
              rows={rows}
              total={total}
              loading={loading}
              selected={target.kind === "event" ? target.id : null}
              filter={filter}
              onSelect={(r) => setTarget({ kind: "event", id: r.id })}
              onLoadMore={loadMore}
              onFilter={setFilter}
              onPin={(key, pid) => {
                if (key) {
                  setFocusedEntity(key);
                  setTarget({ kind: "entity", key });
                  return;
                }
                if (pid != null) {
                  const node = findNodeByPid(tree, pid);
                  if (node) {
                    setFocusedEntity(node.key);
                    setTarget({ kind: "entity", key: node.key });
                  } else {
                    setFilter((f) => ({ ...f, pids: [pid], pidContains: null }));
                  }
                }
              }}
            />
          )}
        </div>

        <Splitter onDelta={(dx) => setRightW((w) => w - dx)} onReset={() => setRightW(360)} />

        <Inspector
          target={target}
          overview={caseInfo}
          findings={findingsList}
          manifest={manifestRows}
          onNavigate={setTarget}
          onFocusEntity={setFocusedEntity}
          onOpenFinding={(f) => {
            setFilter((prev) => ({ ...prev, eventIds: f.evidence, minSeverity: null }));
            if (f.evidence[0] != null) setTarget({ kind: "event", id: f.evidence[0] });
          }}
        />
      </div>
    </div>
  );
}
