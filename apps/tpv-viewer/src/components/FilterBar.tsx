import type { EventFilter, Facet, Severity } from "../api";
import { isFilterNarrowed } from "../api";

const SEVERITIES: Severity[] = ["medium", "high", "critical"];

export function FilterBar({
  filter,
  setFilter,
  sources,
  kinds,
  total,
  matching,
  focus,
  onClearFocus,
  onReset,
}: {
  filter: EventFilter;
  setFilter: (f: EventFilter) => void;
  sources: Facet[];
  kinds: Facet[];
  total: number;
  matching: number;
  /** Label of the entity the timeline is pinned to, if any. */
  focus: string | null;
  onClearFocus: () => void;
  onReset: () => void;
}) {
  const toggleSource = (value: string) => {
    const cur = filter.sources ?? [];
    const next = cur.includes(value) ? cur.filter((s) => s !== value) : [...cur, value];
    setFilter({
      ...filter,
      sources: next,
      kinds: [],
      networkOnly: false,
    });
  };

  const toggleKind = (value: string) => {
    const cur = filter.kinds ?? [];
    const next = cur.includes(value) ? cur.filter((k) => k !== value) : [...cur, value];
    setFilter({
      ...filter,
      kinds: next,
      sources: [],
      networkOnly: false,
    });
  };

  const narrowed = matching !== total;

  return (
    <div className="filterbar">
      <input
        className="search"
        type="search"
        placeholder="id:4688  pid:1234  user:alice  path, image, peer…"
        value={filter.text ?? ""}
        onChange={(e) => setFilter({ ...filter, text: e.target.value || null })}
      />

      <textarea
        className="hunt"
        rows={2}
        placeholder="Hunt IOCs — one hash, IP or name per line"
        value={(filter.iocs ?? []).join("\n")}
        onChange={(e) =>
          setFilter({
            ...filter,
            iocs: e.target.value.length ? e.target.value.split(/\r?\n/) : [],
          })
        }
        spellCheck={false}
      />

      {/* A pinned entity narrows results as hard as any chip does, so it has to
          be visible in the same place, and removable the same way. */}
      {focus && (
        <>
          <div className="sep" />
          <span className="chip on focus" onClick={onClearFocus} title={focus}>
            {focus}
            <span className="n">{"\u00d7"}</span>
          </span>
        </>
      )}

      <div className="sep" />

      <div className="chipset">
        {sources.map((s) => (
          <span
            key={s.value}
            className={`chip${filter.sources?.includes(s.value) ? " on" : ""}`}
            onClick={() => toggleSource(s.value)}
            title={`${s.count.toLocaleString()} events from ${s.value}`}
          >
            {s.value}
            <span className="n">{compact(s.count)}</span>
          </span>
        ))}
      </div>

      {kinds.length > 0 && (
        <>
          <div className="sep" />
          <div className="chipset">
            {kinds.map((k) => (
              <span
                key={k.value}
                className={`chip${filter.kinds?.includes(k.value) ? " on" : ""}`}
                onClick={() => toggleKind(k.value)}
                title={`${k.count.toLocaleString()} ${k.value} events`}
              >
                {shortKind(k.value)}
                <span className="n">{compact(k.count)}</span>
              </span>
            ))}
          </div>
        </>
      )}

      <div className="sep" />

      <span
        className={`chip${filter.networkOnly ? " on" : ""}`}
        onClick={() =>
          setFilter({
            ...filter,
            networkOnly: !filter.networkOnly,
            sources: [],
            kinds: [],
          })
        }
        title="Connections and listeners"
      >
        network
      </span>
      <span
        className={`chip${filter.suspectTimeOnly ? " on" : ""}`}
        onClick={() => setFilter({ ...filter, suspectTimeOnly: !filter.suspectTimeOnly })}
        title="Only events whose timestamp was inferred, absent or out of range"
      >
        suspect time
      </span>

      {SEVERITIES.map((sev) => (
        <span
          key={sev}
          className={`chip sev-${sev}${filter.minSeverity === sev ? " on" : ""}`}
          onClick={() =>
            setFilter({
              ...filter,
              minSeverity: filter.minSeverity === sev ? null : sev,
            })
          }
          title={`Events cited by findings of ${sev} or worse`}
        >
          ≥{sev}
        </span>
      ))}

      <span className="spacer" />

      <span className="badge" title="events matching the current filter">
        {matching.toLocaleString()}
        {narrowed && ` of ${total.toLocaleString()}`}
      </span>
      <button
        onClick={onReset}
        disabled={!narrowed && !focus && !isFilterNarrowed(filter)}
      >
        Clear
      </button>
    </div>
  );
}

function shortKind(kind: string): string {
  return kind.replace(/^(net|process)_/, "");
}

function compact(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1e6) return `${(n / 1000).toFixed(n < 10000 ? 1 : 0)}k`;
  return `${(n / 1e6).toFixed(1)}M`;
}
