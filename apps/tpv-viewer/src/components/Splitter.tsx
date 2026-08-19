import { useCallback, useRef, useState } from "react";

/**
 * A drag handle between two panes.
 *
 * Pointer capture rather than window listeners, so a fast drag that outruns the
 * cursor still delivers its events here instead of to whatever it passes over.
 */
export function Splitter({
  onDelta,
  onReset,
}: {
  /** Pixels moved since the last call, positive to the right. */
  onDelta: (dx: number) => void;
  onReset?: () => void;
}) {
  const last = useRef<number | null>(null);

  const move = useCallback(
    (e: React.PointerEvent) => {
      if (last.current === null) return;
      const dx = e.clientX - last.current;
      last.current = e.clientX;
      if (dx !== 0) onDelta(dx);
    },
    [onDelta],
  );

  return (
    <div
      className="splitter"
      onPointerDown={(e) => {
        last.current = e.clientX;
        e.currentTarget.setPointerCapture(e.pointerId);
      }}
      onPointerMove={move}
      onPointerUp={(e) => {
        last.current = null;
        e.currentTarget.releasePointerCapture(e.pointerId);
      }}
      onDoubleClick={onReset}
      role="separator"
      aria-orientation="vertical"
      title="drag to resize, double-click to reset"
    />
  );
}

/**
 * A number that survives restarting the app.
 *
 * Layout is the sort of thing an analyst adjusts once for their screen and then
 * expects to stay adjusted; losing it on every launch makes the tool feel like
 * it is not paying attention.
 */
export function usePersistentNumber(
  key: string,
  initial: number,
  min: number,
  max: number,
): [number, (next: number | ((cur: number) => number)) => void] {
  const [value, setValue] = useState(() => {
    const saved = Number(localStorage.getItem(key));
    return Number.isFinite(saved) && saved > 0 ? clamp(saved, min, max) : initial;
  });

  const set = useCallback(
    (next: number | ((cur: number) => number)) => {
      setValue((cur) => {
        const raw = typeof next === "function" ? next(cur) : next;
        const v = clamp(raw, min, max);
        localStorage.setItem(key, String(v));
        return v;
      });
    },
    [key, min, max],
  );

  return [value, set];
}

function clamp(v: number, lo: number, hi: number) {
  return Math.min(hi, Math.max(lo, v));
}
