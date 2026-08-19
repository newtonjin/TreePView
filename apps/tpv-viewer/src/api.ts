/**
 * The typed edge of the IPC boundary.
 *
 * Every type here mirrors a Rust struct in `src-tauri/src/commands.rs`. They are
 * hand-written rather than generated because the surface is small and because a
 * mismatch shows up immediately as a type error at the one call site that cares.
 */
import { invoke } from "@tauri-apps/api/core";

export type TsPrecision =
  | "nanosecond"
  | "microsecond"
  | "millisecond"
  | "second"
  | "minute"
  | "hour"
  | "day"
  | "unknown";

export interface Timestamp {
  utc_ns: number;
  precision: TsPrecision;
  tz_source: string;
  flags: number;
}

/** Bit values of `Timestamp.flags`, mirroring `tpv_model::TsFlags`. */
export const TS_OUT_OF_RANGE = 1 << 0;
export const TS_ZERO = 1 << 1;
export const TS_INFERRED = 1 << 2;

/**
 * i64 nanoseconds cannot round-trip through JSON as a JavaScript number
 * (precision is lost past 2004). Bounds used as SQL filters must be padded
 * so the live snapshot sitting on the span's right edge is not dropped.
 */
export const NS_FILTER_PAD = 1_000_000;

export function paddedWindow(view: [number, number] | null): {
  fromNs: number | null;
  toNs: number | null;
} {
  if (!view) return { fromNs: null, toNs: null };
  return { fromNs: view[0] - NS_FILTER_PAD, toNs: view[1] + NS_FILTER_PAD };
}

/** True when the viewport is the whole case, so a time filter would only
 *  drop events to JSON rounding and must not be applied. */
export function isFullSpan(
  view: [number, number] | null,
  span: [number, number] | null,
): boolean {
  if (!view || !span) return true;
  return (
    Math.abs(view[0] - span[0]) <= NS_FILTER_PAD && Math.abs(view[1] - span[1]) <= NS_FILTER_PAD
  );
}

export interface EventRow {
  id: number;
  ts: Timestamp;
  /**
   * The instant already formatted, because `ts.utc_ns` cannot be trusted here:
   * i64 nanoseconds passed JavaScript's 2^53 exact-integer range in 2004, so
   * any date computed in this process would be up to 256 ns off. Use this for
   * anything an analyst reads, and `ts.utc_ns` only for layout arithmetic.
   */
  iso: string;
  ts_end_utc_ns: number | null;
  source: string;
  kind: string;
  entity_key: string | null;
  pid: number | null;
  ppid: number | null;
  image: string | null;
  user: string | null;
  path: string | null;
  remote: string | null;
  log_id: number | null;
  summary: string;
  has_payload: boolean;
}

export interface ProcessStart {
  ns: number;
  /** Formatted in Rust; i64 nanoseconds do not survive a JavaScript number. */
  iso: string;
  /** False when this is when the process was first seen, not when it started. */
  exact: boolean;
}

export interface ProcessNode {
  entity_id: number;
  key: string;
  label: string;
  pid: number | null;
  started: ProcessStart | null;
  image: string | null;
  command_line: string | null;
  user: string | null;
  elevated: boolean | null;
  /** Set when the collector could not open this process, explaining the blanks. */
  access_error: string | null;
  event_count: number;
  first_event_ns: number | null;
  last_event_ns: number | null;
  max_severity: Severity | null;
  children: ProcessNode[];
}

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface TimeBin {
  index: number;
  start_ns: number;
  end_ns: number;
  count: number;
}

export interface EntityRow {
  id: number;
  kind: string;
  key: string;
  label: string;
  first_seen_ns: number | null;
  event_count: number;
  attrs: Record<string, unknown> | null;
}

export interface RelatedEntity {
  kind: string;
  entity: EntityRow;
  outgoing: boolean;
}

export interface HostInfo {
  hostname: string;
  os_name: string;
  os_version: string;
  architecture: string;
  domain: string | null;
  machine_id: string | null;
  timezone_name: string | null;
  utc_offset_minutes: number | null;
  boot_time: Timestamp | null;
}

export interface Custody {
  collector_version: string;
  collector_pid: number;
  collector_image: string;
  collector_sha256: string | null;
  command_line: string;
  started: Timestamp;
  finished: Timestamp;
  run_as_user: string;
  elevated: boolean;
  files_written: string[];
  warnings: string[];
}

export interface CaseMeta {
  format_version: number;
  case_id: string;
  tool_version: string;
  created_utc_ns: number;
  host: HostInfo;
  clock: { host_utc: Timestamp; monotonic_uptime_ms: number | null };
  profile: Record<string, unknown>;
  custody: Custody | null;
  finalized: boolean;
  content_digest: string | null;
}

export interface Counts {
  events: number;
  entities: number;
  edges: number;
  blobs: number;
  manifest_entries: number;
  findings: number;
}

export interface Facet {
  value: string;
  count: number;
}

export interface Gap {
  sourcePath: string;
  method: string;
  error: string;
}

export interface CaseOverview {
  path: string;
  meta: CaseMeta;
  counts: Counts;
  span: [number, number] | null;
  sources: Facet[];
  kinds: Facet[];
  gaps: Gap[];
}

export interface ManifestEntry {
  source_path: string;
  method: string;
  size_bytes: number;
  sha256: string | null;
  started: Timestamp;
  finished: Timestamp;
  events_emitted: number;
  error: string | null;
}

export interface EventDetail {
  event: EventRow;
  payload: unknown | null;
  entity: EntityRow | null;
  related: RelatedEntity[];
  provenance: ManifestEntry | null;
}

export interface EntityDetail {
  entity: EntityRow;
  related: RelatedEntity[];
  recent: EventRow[];
}

export interface EventPage {
  rows: EventRow[];
  total: number;
  offset: number;
}

export interface VerifyReport {
  finalized: boolean;
  digestMatches: boolean;
  sealedDigest: string | null;
}

/**
 * Mirrors `tpv_format::EventFilter`. Every field is optional on the Rust side,
 * so omitting one widens the query rather than breaking it.
 */
export interface EventFilter {
  fromNs?: number | null;
  toNs?: number | null;
  pids?: number[];
  sources?: string[];
  kinds?: string[];
  entityKey?: string | null;
  eventIds?: number[];
  text?: string | null;
  imageContains?: string | null;
  pathContains?: string | null;
  remoteContains?: string | null;
  userContains?: string | null;
  sourceContains?: string | null;
  kindContains?: string | null;
  summaryContains?: string | null;
  pidContains?: string | null;
  logIds?: number[];
  logIdContains?: string | null;
  logsOnly?: boolean;
  networkOnly?: boolean;
  suspectTimeOnly?: boolean;
  minSeverity?: Severity | null;
  iocs?: string[];
}

export interface Finding {
  rule: string;
  severity: Severity;
  confidence: "low" | "medium" | "high";
  title: string;
  detail: string;
  evidence: number[];
  entity_key?: string | null;
}

export const openCase = (path: string) => invoke<CaseOverview>("open_case", { path });
export const closeCase = () => invoke<void>("close_case");
export const overview = () => invoke<CaseOverview>("overview");
export const processTree = () => invoke<ProcessNode[]>("process_tree");
export const manifest = () => invoke<ManifestEntry[]>("manifest");
export const findings = () => invoke<Finding[]>("findings");
export const verify = () => invoke<VerifyReport>("verify");

export const queryEvents = (filter: EventFilter, limit: number, offset: number) =>
  invoke<EventPage>("query_events", { filter, limit, offset });

export const histogram = (filter: EventFilter, fromNs: number, toNs: number, bins: number) =>
  invoke<TimeBin[]>("histogram", { filter, fromNs, toNs, bins });

export const inspectEvent = (id: number) => invoke<EventDetail>("inspect_event", { id });
export const inspectEntity = (key: string) => invoke<EntityDetail>("inspect_entity", { key });

export const exportEvents = (path: string, format: "csv" | "jsonl" | "md", filter: EventFilter) =>
  invoke<void>("export_events", { path, format, filter });

const nonempty = (s: string | null | undefined): boolean => Boolean(s && s.trim());

/** True when any analyst-controlled constraint is active (not the timeline). */
export function isFilterNarrowed(f: EventFilter): boolean {
  return Boolean(
    nonempty(f.text) ||
      nonempty(f.imageContains) ||
      nonempty(f.pathContains) ||
      nonempty(f.remoteContains) ||
      nonempty(f.userContains) ||
      nonempty(f.sourceContains) ||
      nonempty(f.kindContains) ||
      nonempty(f.summaryContains) ||
      nonempty(f.pidContains) ||
      nonempty(f.logIdContains) ||
      (f.logIds && f.logIds.length > 0) ||
      f.networkOnly ||
      f.suspectTimeOnly ||
      f.logsOnly ||
      (f.kinds && f.kinds.length > 0) ||
      (f.sources && f.sources.length > 0) ||
      (f.pids && f.pids.length > 0) ||
      (f.iocs && f.iocs.some((l) => l.trim().length > 0)) ||
      Boolean(f.minSeverity),
  );
}
