/**
 * Display helpers.
 *
 * Note what is *not* here: converting a raw `utc_ns` into a date. Those numbers
 * are i64 nanoseconds, which have exceeded JavaScript's exact-integer range
 * since 2004, so any timestamp shown to the analyst is formatted in Rust and
 * arrives as `EventRow.iso`. The functions below only ever use the numbers for
 * layout arithmetic and for axis labels, where being a few hundred nanoseconds
 * out is invisible.
 */
import { TS_INFERRED, TS_OUT_OF_RANGE, TS_ZERO, type Timestamp } from "./api";

const NS_PER_MS = 1e6;

/** Approximate wall-clock date, for axis ticks only. */
export function axisDate(ns: number): Date {
  return new Date(ns / NS_PER_MS);
}

const PAD = (n: number, w = 2) => String(n).padStart(w, "0");

/** Axis tick label, its detail chosen to suit the span currently on screen. */
export function axisLabel(ns: number, spanNs: number): string {
  const d = axisDate(ns);
  if (spanNs > 60 * 86400e9) return `${d.getUTCFullYear()}-${PAD(d.getUTCMonth() + 1)}`;
  if (spanNs > 2 * 86400e9) return `${PAD(d.getUTCMonth() + 1)}-${PAD(d.getUTCDate())}`;
  if (spanNs > 2 * 3600e9) return `${PAD(d.getUTCHours())}:${PAD(d.getUTCMinutes())}`;
  if (spanNs > 2 * 60e9) return `${PAD(d.getUTCHours())}:${PAD(d.getUTCMinutes())}:${PAD(d.getUTCSeconds())}`;
  return `${PAD(d.getUTCMinutes())}:${PAD(d.getUTCSeconds())}.${PAD(d.getUTCMilliseconds(), 3)}`;
}

export function duration(ns: number): string {
  const abs = Math.abs(ns);
  if (abs < 1e3) return `${ns} ns`;
  if (abs < 1e6) return `${(ns / 1e3).toFixed(1)} us`;
  if (abs < 1e9) return `${(ns / 1e6).toFixed(1)} ms`;
  if (abs < 60e9) return `${(ns / 1e9).toFixed(2)} s`;
  if (abs < 3600e9) return `${(ns / 60e9).toFixed(1)} min`;
  if (abs < 86400e9) return `${(ns / 3600e9).toFixed(1)} h`;
  return `${(ns / 86400e9).toFixed(1)} d`;
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

/** Why a timestamp is untrustworthy, or null when it is fine. */
export function suspectReason(ts: Timestamp): string | null {
  if (ts.flags & TS_ZERO) return "the source stored no value";
  if (ts.flags & TS_OUT_OF_RANGE) return "outside the representable range";
  if (ts.flags & TS_INFERRED) return "observed at collection, not when it happened";
  return null;
}

export function isSuspect(ts: Timestamp): boolean {
  return ts.flags !== 0;
}

/** Last path component, for showing a binary without its directory. */
export function baseName(path: string): string {
  const i = Math.max(path.lastIndexOf("\\"), path.lastIndexOf("/"));
  return i >= 0 ? path.slice(i + 1) : path;
}
