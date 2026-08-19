import { describe, expect, it } from "vitest";
import { NS_FILTER_PAD, isFilterNarrowed, isFullSpan, paddedWindow } from "./api";

describe("paddedWindow", () => {
  it("pads both edges so a live snapshot sitting on the span max is not dropped", () => {
    // These values are what JSON does to i64 nanoseconds around 2026: the
    // true collection instant can sit up to a few hundred ns past the rounded
    // span max, which is enough to hide every inferred event.
    const span: [number, number] = [1.7870564423061164e18, 1.7870964063607703e18];
    const w = paddedWindow(span);
    expect(w.fromNs).toBe(span[0] - NS_FILTER_PAD);
    expect(w.toNs).toBe(span[1] + NS_FILTER_PAD);
    expect(w.toNs! - span[1]).toBeGreaterThan(256);
  });

  it("is a no-op when there is no view", () => {
    expect(paddedWindow(null)).toEqual({ fromNs: null, toNs: null });
  });
});

describe("isFullSpan", () => {
  it("treats a viewport matching the case span as unfiltered", () => {
    const span: [number, number] = [1e18, 2e18];
    expect(isFullSpan(span, span)).toBe(true);
    expect(isFullSpan([span[0] + 10, span[1]], span)).toBe(true);
    expect(isFullSpan([span[0], span[0] + 1e15], span)).toBe(false);
  });

  it("does not time-filter when either bound is missing", () => {
    expect(isFullSpan(null, [1, 2])).toBe(true);
    expect(isFullSpan([1, 2], null)).toBe(true);
  });
});

describe("isFilterNarrowed", () => {
  it("is false for an empty filter", () => {
    expect(isFilterNarrowed({})).toBe(false);
  });

  it("treats a column substring as a real constraint", () => {
    expect(isFilterNarrowed({ pathContains: "Security" })).toBe(true);
    expect(isFilterNarrowed({ pidContains: "12" })).toBe(true);
    expect(isFilterNarrowed({ logsOnly: true })).toBe(true);
  });

  it("treats hunt IOCs and a severity floor as constraints", () => {
    expect(isFilterNarrowed({ iocs: ["203.0.113.7"] })).toBe(true);
    expect(isFilterNarrowed({ minSeverity: "high" })).toBe(true);
    expect(isFilterNarrowed({ iocs: ["", "  "] })).toBe(false);
  });
});
