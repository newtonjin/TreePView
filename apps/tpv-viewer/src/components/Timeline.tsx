import { useEffect, useRef, useState } from "react";
import { histogramLanes, type EventFilter, type LaneSeries, type TimeBin } from "../api";
import { axisLabel, duration } from "../format";

const OVERVIEW_H = 26;
const AXIS_H = 16;
const LANE_H = 18;
const GUTTER = 44;
const EMPTY_PLOT = 48;

const LANES: { id: string; label: string; color: string }[] = [
  { id: "start", label: "start", color: "#4c9aff" },
  { id: "exit", label: "exit", color: "#8b98a8" },
  { id: "exec", label: "exec", color: "#c586e0" },
  { id: "logon", label: "logon", color: "#7fd4a2" },
  { id: "svc", label: "svc", color: "#ffc44c" },
  { id: "task", label: "task", color: "#ff8a4c" },
  { id: "net", label: "net", color: "#3dbae0" },
  { id: "evtx", label: "evtx", color: "#e06c75" },
  { id: "other", label: "other", color: "#5d6977" },
];

const LANE_COLOR = Object.fromEntries(LANES.map((l) => [l.id, l.color]));
const LANE_LABEL = Object.fromEntries(LANES.map((l) => [l.id, l.label]));

/**
 * The zoomed-out timeline.
 *
 * Density is drawn as stacked lanes rather than one histogram because a live
 * snapshot or a module-load storm would otherwise drown the 4688 / logon /
 * network rows the analyst actually correlates. Each lane scales on its own
 * peak so a handful of process starts stay visible next to a busy band.
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
  const [lanes, setLanes] = useState<LaneSeries[]>([]);
  const [overview, setOverview] = useState<LaneSeries[]>([]);
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
    histogramLanes(filter, view[0], view[1], binCount)
      .then((b) => live && setLanes(b))
      .catch(() => live && setLanes([]));
    return () => {
      live = false;
    };
  }, [filter, view[0], view[1], binCount]);

  // The overview strip always shows the whole case, so it deliberately ignores
  // the time bounds of the filter while still respecting its other dimensions.
  useEffect(() => {
    let live = true;
    const wide = { ...filter, fromNs: null, toNs: null };
    histogramLanes(wide, span[0], span[1], Math.max(40, Math.floor(width / 3)))
      .then((b) => live && setOverview(b))
      .catch(() => live && setOverview([]));
    return () => {
      live = false;
    };
  }, [filter, span[0], span[1], width]);

  const plotH = lanes.length > 0 ? lanes.length * LANE_H : EMPTY_PLOT;
  const height = plotH + AXIS_H + OVERVIEW_H;

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.max(1, Math.floor(width * dpr));
    canvas.height = Math.floor(height * dpr);
    canvas.style.height = `${height}px`;
    const g = canvas.getContext("2d");
    if (!g) return;
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    draw(g, width, height, plotH, lanes, overview, span, view, marks, drag, hover);
  }, [width, height, plotH, lanes, overview, span, view, marks, drag, hover]);

  const xToNs = (x: number) => {
    const inner = Math.max(1, width - GUTTER);
    const px = Math.max(0, x - GUTTER);
    return view[0] + ((view[1] - view[0]) * px) / inner;
  };

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
      {lanes.length > 0 && (
        <div className="tl-legend">
          {lanes.map((s) => (
            <span key={s.lane} className="tl-leg">
              <i style={{ background: LANE_COLOR[s.lane] ?? "#5d6977" }} />
              {LANE_LABEL[s.lane] ?? s.lane}
            </span>
          ))}
        </div>
      )}
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
  h: number,
  plotH: number,
  lanes: LaneSeries[],
  overview: LaneSeries[],
  span: [number, number],
  view: [number, number],
  marks: Mark[],
  drag: { from: number; to: number } | null,
  hover: number | null,
) {
  g.clearRect(0, 0, w, h);
  const inner = Math.max(1, w - GUTTER);

  if (lanes.length === 0) {
    g.fillStyle = "#5d6977";
    g.font = '11px ui-monospace, Consolas, monospace';
    g.textBaseline = "middle";
    g.fillText("no events in this window", GUTTER, plotH / 2);
  } else {
    lanes.forEach((series, i) => {
      const y0 = i * LANE_H;
      const peak = Math.max(1, ...series.bins.map((b) => b.count));
      const bw = inner / Math.max(1, series.bins.length);
      g.fillStyle = i % 2 === 0 ? "#0f151c" : "#0d1117";
      g.fillRect(GUTTER, y0, inner, LANE_H);

      g.fillStyle = "#5d6977";
      g.font = '10px ui-monospace, Consolas, monospace';
      g.textBaseline = "middle";
      g.textAlign = "right";
      g.fillText(LANE_LABEL[series.lane] ?? series.lane, GUTTER - 6, y0 + LANE_H / 2);
      g.textAlign = "left";

      const color = LANE_COLOR[series.lane] ?? "#5d6977";
      for (const b of series.bins) {
        if (b.count === 0) continue;
        // Square root rather than linear: a single beacon callback next to a
        // ten-thousand-event log flush would otherwise be one invisible pixel.
        const bh = Math.max(1, (Math.sqrt(b.count) / Math.sqrt(peak)) * (LANE_H - 4));
        g.fillStyle = color;
        g.fillRect(GUTTER + b.index * bw, y0 + LANE_H - 2 - bh, Math.max(1, bw - 0.4), bh);
      }
    });
  }

  g.strokeStyle = "#222c38";
  g.lineWidth = 1;
  g.beginPath();
  g.moveTo(GUTTER, plotH + 0.5);
  g.lineTo(w, plotH + 0.5);
  g.stroke();

  // --- axis ---
  const viewSpan = view[1] - view[0];
  const ticks = Math.max(2, Math.floor(inner / 130));
  g.fillStyle = "#5d6977";
  g.font = '10px ui-monospace, Consolas, monospace';
  g.textBaseline = "top";
  for (let i = 0; i <= ticks; i++) {
    const x = GUTTER + (inner * i) / ticks;
    const ns = view[0] + (viewSpan * i) / ticks;
    g.textAlign = i === 0 ? "left" : i === ticks ? "right" : "center";
    g.fillText(axisLabel(ns, viewSpan), Math.min(w - 1, Math.max(GUTTER + 1, x)), plotH + 3);
  }

  // --- overview strip, with the current view framed inside it ---
  const oy = plotH + AXIS_H;
  g.fillStyle = "#0d1117";
  g.fillRect(0, oy, w, OVERVIEW_H);

  const summed = sumOverview(overview);
  const opeak = Math.max(1, ...summed.map((b) => b.count));
  const obw = inner / Math.max(1, summed.length);
  for (const b of summed) {
    if (b.count === 0) continue;
    const bh = Math.max(1, (Math.sqrt(b.count) / Math.sqrt(opeak)) * (OVERVIEW_H - 6));
    g.fillStyle = "#2b4560";
    g.fillRect(GUTTER + b.index * obw, oy + OVERVIEW_H - 3 - bh, Math.max(1, obw - 0.5), bh);
  }

  const total = Math.max(1, span[1] - span[0]);
  const vx0 = GUTTER + ((view[0] - span[0]) / total) * inner;
  const vx1 = GUTTER + ((view[1] - span[0]) / total) * inner;
  g.fillStyle = "rgba(76,154,255,0.16)";
  g.fillRect(vx0, oy, Math.max(2, vx1 - vx0), OVERVIEW_H);
  g.strokeStyle = "#4c9aff";
  g.strokeRect(vx0 + 0.5, oy + 0.5, Math.max(2, vx1 - vx0) - 1, OVERVIEW_H - 1);

  // --- annotations ---
  for (const m of marks) {
    if (m.ns < view[0] || m.ns > view[1]) continue;
    const x = GUTTER + ((m.ns - view[0]) / Math.max(1, viewSpan)) * inner;
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
  if (hover !== null && hover >= GUTTER) {
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

function sumOverview(lanes: LaneSeries[]): TimeBin[] {
  if (lanes.length === 0) return [];
  const n = lanes[0].bins.length;
  return lanes[0].bins.map((_, i) => {
    let count = 0;
    for (const s of lanes) count += s.bins[i]?.count ?? 0;
    return { ...lanes[0].bins[i], count };
  }).slice(0, n);
}
