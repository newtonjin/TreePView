import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Fixed-height row windowing.
 *
 * A case can hold millions of events and a live host produces thousands of
 * processes, so neither list can be mounted in full: the DOM node count, not the
 * query, is what makes a viewer feel slow. Rows are a fixed height here, which
 * makes the mapping from scroll offset to row index pure arithmetic and avoids
 * the measurement pass a variable-height virtualizer needs.
 */
export function useVirtual(count: number, rowHeight: number, overscan = 12) {
  const ref = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [height, setHeight] = useState(600);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setHeight(el.clientHeight));
    ro.observe(el);
    setHeight(el.clientHeight);
    return () => ro.disconnect();
  }, []);

  // A shorter result (chip filter, search) must not keep the old scroll offset:
  // that window sits past the last row and the list renders blank while the
  // footer still says the rows are loaded.
  useEffect(() => {
    const el = ref.current;
    const max = Math.max(0, count * rowHeight - (el?.clientHeight ?? height));
    if (scrollTop > max) {
      if (el) el.scrollTop = 0;
      setScrollTop(0);
    }
  }, [count, rowHeight, height, scrollTop]);

  const onScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(e.currentTarget.scrollTop);
  }, []);

  const maxFirst = Math.max(0, count - 1);
  const first = Math.min(maxFirst, Math.max(0, Math.floor(scrollTop / rowHeight) - overscan));
  const visible = Math.ceil(height / rowHeight) + overscan * 2;
  const last = Math.min(count, first + visible);

  const scrollToRow = useCallback(
    (index: number) => {
      const el = ref.current;
      if (!el) return;
      const top = index * rowHeight;
      // Only scroll when the row is actually outside the viewport, so selecting
      // a visible row does not yank the list under the analyst's cursor.
      if (top < el.scrollTop || top + rowHeight > el.scrollTop + el.clientHeight) {
        el.scrollTop = top - el.clientHeight / 2 + rowHeight / 2;
      }
    },
    [rowHeight],
  );

  return {
    ref,
    onScroll,
    first,
    last,
    padTop: first * rowHeight,
    totalHeight: count * rowHeight,
    scrollToRow,
  };
}
