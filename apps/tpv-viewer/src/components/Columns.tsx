import { useCallback, useRef, useState } from "react";

export interface ColumnSpec {
  id: string;
  label: string;
  /** Starting width in pixels. The last flexible column ignores this. */
  width: number;
  min?: number;
  /** Exactly one column should flex, absorbing the leftover width. */
  flex?: boolean;
  align?: "left" | "right";
}

export type Widths = Record<string, number>;

/**
 * Column widths with drag-to-resize, persisted per table.
 *
 * Widths live here rather than in CSS because a forensic table is read by
 * scanning one column at a time: an analyst comparing command lines wants that
 * column wide and everything else out of the way, and the right proportions
 * differ for every case.
 */
export function useColumns(storageKey: string, spec: ColumnSpec[]) {
  const [widths, setWidths] = useState<Widths>(() => {
    const base: Widths = {};
    for (const c of spec) base[c.id] = c.width;
    try {
      const saved = JSON.parse(localStorage.getItem(storageKey) ?? "{}") as Widths;
      for (const c of spec) {
        const v = saved[c.id];
        if (typeof v === "number" && v > 0) base[c.id] = v;
      }
    } catch {
      // A corrupt preference is not worth failing over; fall back to defaults.
    }
    return base;
  });

  const resize = useCallback(
    (id: string, dx: number) => {
      setWidths((cur) => {
        const min = spec.find((c) => c.id === id)?.min ?? 40;
        const next = { ...cur, [id]: Math.max(min, (cur[id] ?? 100) + dx) };
        localStorage.setItem(storageKey, JSON.stringify(next));
        return next;
      });
    },
    [spec, storageKey],
  );

  const reset = useCallback(() => {
    const base: Widths = {};
    for (const c of spec) base[c.id] = c.width;
    localStorage.setItem(storageKey, JSON.stringify(base));
    setWidths(base);
  }, [spec, storageKey]);

  return { widths, resize, reset };
}

export function ColumnHeader({
  spec,
  widths,
  onResize,
  onReset,
  filters,
  onFilter,
}: {
  spec: ColumnSpec[];
  widths: Widths;
  onResize: (id: string, dx: number) => void;
  onReset: () => void;
  /** Per-column substring filters. Omit to keep a single-line header. */
  filters?: Record<string, string>;
  onFilter?: (id: string, value: string) => void;
}) {
  return (
    <div className={`col-head${onFilter ? " with-filters" : ""}`}>
      {spec.map((c, i) => (
        <div
          key={c.id}
          className={`col-cell${c.align === "right" ? " right" : ""}`}
          style={cellStyle(c, widths)}
        >
          <span className="col-title">{c.label}</span>
          {onFilter && c.id !== "time" && (
            <input
              className="col-filter"
              type="search"
              placeholder="filter"
              value={filters?.[c.id] ?? ""}
              onChange={(e) => onFilter(c.id, e.target.value)}
              onClick={(e) => e.stopPropagation()}
              onKeyDown={(e) => e.stopPropagation()}
              spellCheck={false}
            />
          )}
          {i < spec.length - 1 && (
            <ColumnGrip onDelta={(dx) => onResize(c.id, dx)} onReset={onReset} />
          )}
        </div>
      ))}
    </div>
  );
}

function ColumnGrip({
  onDelta,
  onReset,
}: {
  onDelta: (dx: number) => void;
  onReset: () => void;
}) {
  const last = useRef<number | null>(null);
  return (
    <div
      className="col-grip"
      onPointerDown={(e) => {
        e.stopPropagation();
        last.current = e.clientX;
        e.currentTarget.setPointerCapture(e.pointerId);
      }}
      onPointerMove={(e) => {
        if (last.current === null) return;
        const dx = e.clientX - last.current;
        last.current = e.clientX;
        if (dx !== 0) onDelta(dx);
      }}
      onPointerUp={(e) => {
        last.current = null;
        e.currentTarget.releasePointerCapture(e.pointerId);
      }}
      onDoubleClick={(e) => {
        e.stopPropagation();
        onReset();
      }}
      title="drag to resize, double-click to reset all"
    />
  );
}

/** Width style for a cell, matching what the header uses. */
export function cellStyle(c: ColumnSpec, widths: Widths): React.CSSProperties {
  if (c.flex) return { flex: 1, minWidth: c.min ?? 80 };
  const w = widths[c.id] ?? c.width;
  return { width: w, flex: `0 0 ${w}px` };
}
