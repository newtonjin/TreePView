import { useEffect, useRef, useState } from "react";
import { histogram, type EventFilter, type TimeBin } from "../api";
import { axisLabel, duration } from "../format";

const HEIGHT = 132;
const OVERVIEW_H = 26;
const AXIS_H = 16;

/**
 * The zoomed-out timeline.
 *
 * Density is drawn as a histogram rather than as individual marks because at any
 * useful zoom there are far more events than pixels, and drawing one rectangle
 * per event would both stall the canvas and produce a solid block that tells the
 * analyst nothing. The bucketing happens in SQL, so the cost of "show me a year"
 * equals the cost of "show me a second": a few hundred integers either way.
 */
export interface Mark {
  ns: number;
  label: string;
}

export function Timeline({
  filter,
  span,
  view,
  marks,
  onView,
}: {
  filter: EventFilter;
  span: [number, number];
  view: [number, number];
  marks: Mark[];
  onView: (v: [number, number]) => void;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const boxRef = useRef<HTMLDivElement>(null);
  const [bins, setBins] = useState<TimeBin[]>([]);
  const [overview, setOverview] = useState<TimeBin[]>([]);
  const [drag, setDrag] = useState<{ from: number; to: number } | null>(null);
  const [hover, setHover] = useState<number | null>(null);
  const [width, setWidth] = useState(900);

  useEffect(() => {
    const el = boxRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setWidth(el.clientWidth));
    ro.observe(el);
    setWidth(el.clientWidth);
    return () => ro.disconnect();
  }, []);

  // One bin per two pixels: finer than the display can resolve is wasted work,
  // coarser makes the histogram look blocky as the window widens.
  const binCount = Math.max(40, Math.min(2000, Math.floor(width / 2)));

  useEffect(() => {
    let live = true;
    histogram(filter, view[0], view[1], binCount)
      .then((b) => live && setBins(b))
      .catch(() => live && setBins([]));
    return () => {
      live = false;
    };
  }, [filter, view[0], view[1], binCount]);

  // The overview strip always shows the whole case, so it deliberately ignores
  // the time bounds of the filter while still respecting its other dimensions.
  useEffect(() => {
    let live = true;
    const wide = { ...filter, fromNs: null, toNs: null };
    histogram(wide, span[0], span[1], Math.max(40, Math.floor(width / 3)))
      .then((b) => live && setOverview(b))
      .catch(() => live && setOverview([]));
    return () => {
      live = false;
    };
  }, [filter, span[0], span[1], width]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.max(1, Math.floor(width * dpr));
    canvas.height = Math.floor(HEIGHT * dpr);
    canvas.style.height = `${HEIGHT}px`;
    const g = canvas.getContext("2d");
    if (!g) return;
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    draw(g, width, bins, overview, span, view, marks, drag, hover);
  }, [width, bins, overview, span, view, marks, drag, hover]);

  const xToNs = (x: number) => view[0] + ((view[1] - view[0]) * x) / Math.max(1, width);

  const onWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const rect = e.currentTarget.getBoundingClientRect();
    const anchor = xToNs(e.clientX - rect.left);
    const factor = e.deltaY > 0 ? 1.35 : 1 / 1.35;
    // Zooming about the cursor rather than the centre keeps whatever the analyst
    // is pointing at under the pointer, which is what makes drilling into a
    // burst of activity feel direct.
    let from = anchor - (anchor - view[0]) * factor;
    let to = anchor + (view[1] - anchor) * factor;
    const MIN_SPAN = 1000;
    if (to - from < MIN_SPAN) return;
    from = Math.max(span[0], from);
    to = Math.min(span[1], to);
    if (to > from) onView([Math.round(from), Math.round(to)]);
  };

  return (
    <div className="timeline" ref={boxRef}>
      <canvas
        ref={canvasRef}
        onWheel={onWheel}
        onMouseDown={(e) => {
          const rect = e.currentTarget.getBoundingClientRect();
          const x = e.clientX - rect.left;
          setDrag({ from: x, to: x });
        }}
        onMouseMove={(e) => {
          const rect = e.currentTarget.getBoundingClientRect();
          const x = e.clientX - rect.left;
          setHover(x);
          setDrag((d) => (d ? { ...d, to: x } : null));
        }}
        onMouseLeave={() => {
          setHover(null);
          setDrag(null);
        }}
        onMouseUp={() => {
          if (!drag) return;
          const [a, b] = [Math.min(drag.from, drag.to), Math.max(drag.from, drag.to)];
          setDrag(null);
          // A click is a drag of zero width. Treating a stray 3-pixel wobble as a
          // zoom would make the timeline impossible to click on.
          if (b - a < 4) return;
          onView([Math.round(xToNs(a)), Math.round(xToNs(b))]);
        }}
        onDoubleClick={() => onView([span[0], span[1]])}
      />
      <div className="hint">
        {duration(view[1] - view[0])} shown
        {hover !== null && ` \u2022 ${axisLabel(xToNs(hover), view[1] - view[0])}`}
        {" \u2022 drag to zoom, double-click to reset"}
      </div>
    </div>
  );
}

function draw(
  g: CanvasRenderingContext2D,
  w: number,
  bins: TimeBin[],
  overview: TimeBin[],
  span: [number, number],
  view: [number, number],
  marks: Mark[],
  drag: { from: number; to: number } | null,
  hover: number | null,
) {
  const plotH = HEIGHT - OVERVIEW_H - AXIS_H;
  g.clearRect(0, 0, w, HEIGHT);

  // --- density plot ---
  const peak = Math.max(1, ...bins.map((b) => b.count));
  const bw = w / Math.max(1, bins.length);

  for (const b of bins) {
    if (b.count === 0) continue;
    // Square root rather than linear: a single beacon callback next to a
    // ten-thousand-event log flush would otherwise be one invisible pixel, and
    // the rare event is usually the one worth seeing.
    const h = Math.max(1, (Math.sqrt(b.count) / Math.sqrt(peak)) * (plotH - 4));
    const x = b.index * bw;
    g.fillStyle = "#3d7fd6";
    g.fillRect(x, plotH - h, Math.max(1, bw - 0.5), h);
  }

  g.strokeStyle = "#222c38";
  g.lineWidth = 1;
  g.beginPath();
  g.moveTo(0, plotH + 0.5);
  g.lineTo(w, plotH + 0.5);
  g.stroke();

  // --- axis ---
  const viewSpan = view[1] - view[0];
  const ticks = Math.max(2, Math.floor(w / 130));
  g.fillStyle = "#5d6977";
  g.font = '10px ui-monospace, Consolas, monospace';
  g.textBaseline = "top";
  for (let i = 0; i <= ticks; i++) {
    const x = (w * i) / ticks;
    const ns = view[0] + (viewSpan * i) / ticks;
    g.textAlign = i === 0 ? "left" : i === ticks ? "right" : "center";
    g.fillText(axisLabel(ns, viewSpan), Math.min(w - 1, Math.max(1, x)), plotH + 3);
  }

  // --- overview strip, with the current view framed inside it ---
  const oy = plotH + AXIS_H;
  g.fillStyle = "#0d1117";
  g.fillRect(0, oy, w, OVERVIEW_H);

  const opeak = Math.max(1, ...overview.map((b) => b.count));
  const obw = w / Math.max(1, overview.length);
  for (const b of overview) {
    if (b.count === 0) continue;
    const h = Math.max(1, (Math.sqrt(b.count) / Math.sqrt(opeak)) * (OVERVIEW_H - 6));
    g.fillStyle = "#2b4560";
    g.fillRect(b.index * obw, oy + OVERVIEW_H - 3 - h, Math.max(1, obw - 0.5), h);
  }

  const total = Math.max(1, span[1] - span[0]);
  const vx0 = ((view[0] - span[0]) / total) * w;
  const vx1 = ((view[1] - span[0]) / total) * w;
  g.fillStyle = "rgba(76,154,255,0.16)";
  g.fillRect(vx0, oy, Math.max(2, vx1 - vx0), OVERVIEW_H);
  g.strokeStyle = "#4c9aff";
  g.strokeRect(vx0 + 0.5, oy + 0.5, Math.max(2, vx1 - vx0) - 1, OVERVIEW_H - 1);

  // --- annotations ---
  // A live snapshot lands almost entirely on one instant, because a running
  // service or an open socket has no time of its own beyond "when we looked".
  // Labelling that instant is what stops the resulting spike from reading as a
  // burst of activity on the host.
  for (const m of marks) {
    if (m.ns < view[0] || m.ns > view[1]) continue;
    const x = ((m.ns - view[0]) / Math.max(1, viewSpan)) * w;
    g.strokeStyle = "#c586e0";
    g.setLineDash([3, 3]);
    g.beginPath();
    g.moveTo(x + 0.5, 0);
    g.lineTo(x + 0.5, plotH);
    g.stroke();
    g.setLineDash([]);

    g.fillStyle = "#c586e0";
    g.textBaseline = "top";
    const flip = x > w - 90;
    g.textAlign = flip ? "right" : "left";
    g.fillText(m.label, flip ? x - 4 : x + 4, 3);
  }

  // --- interaction overlays ---
  if (hover !== null) {
    g.strokeStyle = "#4c9aff66";
    g.beginPath();
    g.moveTo(hover + 0.5, 0);
    g.lineTo(hover + 0.5, plotH);
    g.stroke();
  }

  if (drag && Math.abs(drag.to - drag.from) >= 4) {
    const a = Math.min(drag.from, drag.to);
    const b = Math.max(drag.from, drag.to);
    g.fillStyle = "rgba(76,154,255,0.22)";
    g.fillRect(a, 0, b - a, plotH);
    g.strokeStyle = "#4c9aff";
    g.beginPath();
    g.moveTo(a + 0.5, 0);
    g.lineTo(a + 0.5, plotH);
    g.moveTo(b + 0.5, 0);
    g.lineTo(b + 0.5, plotH);
    g.stroke();
  }
}
