import { Fragment, useEffect, useState } from "react";
import {
  inspectEntity,
  inspectEvent,
  type CaseOverview,
  type EntityDetail,
  type EventDetail,
  type EventRow,
  type Finding,
  type ManifestEntry,
  type RelatedEntity,
} from "../api";
import { bytes, suspectReason } from "../format";
import { copyText, selectionText } from "../report";
import { useArtifactMenu } from "./ContextMenu";

type Target =
  | { kind: "event"; id: number }
  | { kind: "entity"; key: string }
  | { kind: "case" };

/**
 * The provenance panel.
 *
 * Its job is to answer "where did this come from", not just "what does this
 * say". Every event shows the artifact it was parsed out of, how that artifact
 * was acquired and the hash of the acquired bytes, because a timeline entry an
 * analyst cannot trace back to a source is not evidence.
 */
export function Inspector({
  target,
  overview,
  findings,
  manifest,
  onNavigate,
  onFocusEntity,
  onOpenFinding,
}: {
  target: Target;
  overview: CaseOverview | null;
  findings: Finding[];
  manifest: ManifestEntry[];
  onNavigate: (t: Target) => void;
  onFocusEntity: (key: string) => void;
  onOpenFinding: (f: Finding) => void;
}) {
  const [event, setEvent] = useState<EventDetail | null>(null);
  const [entity, setEntity] = useState<EntityDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const menu = useArtifactMenu();

  useEffect(() => {
    setError(null);
    if (target.kind === "event") {
      setEntity(null);
      inspectEvent(target.id).then(setEvent).catch((e) => setError(String(e)));
    } else if (target.kind === "entity") {
      setEvent(null);
      inspectEntity(target.key).then(setEntity).catch((e) => setError(String(e)));
    } else {
      setEvent(null);
      setEntity(null);
    }
  }, [target.kind, (target as { id?: number }).id, (target as { key?: string }).key]);

  return (
    <div className="pane">
      <div className="pane-head">
        <span>Inspector</span>
        <span className="spacer" />
        {target.kind !== "case" && (
          <button onClick={() => onNavigate({ kind: "case" })}>Case</button>
        )}
      </div>
      <div
        className="pane-body"
        onContextMenu={(e) => {
          const el = (e.target as HTMLElement | null)?.closest?.("[data-copy]") as HTMLElement | null;
          if (el?.dataset.copy) {
            menu.openFields(
              e,
              [{ label: el.dataset.copyLabel || "value", value: el.dataset.copy }],
              el.dataset.copyLabel,
            );
            return;
          }
          const selected = selectionText().trim();
          if (selected) {
            menu.open(e, [
              {
                label: "Copy selection",
                action: () => {
                  void copyText(selected).then(() => menu.copied("selection"));
                },
              },
            ]);
          }
        }}
      >
        <div className="insp">
          {error && <div className="err">{error}</div>}
          {target.kind === "case" && overview && (
            <CasePanel
              o={overview}
              findings={findings}
              manifest={manifest}
              onOpenFinding={onOpenFinding}
            />
          )}
          {event && <EventPanel d={event} onNavigate={onNavigate} />}
          {entity && (
            <EntityPanel d={entity} onNavigate={onNavigate} onFocusEntity={onFocusEntity} />
          )}
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ case --- */

function CasePanel({
  o,
  findings,
  manifest,
  onOpenFinding,
}: {
  o: CaseOverview;
  findings: Finding[];
  manifest: ManifestEntry[];
  onOpenFinding: (f: Finding) => void;
}) {
  const c = o.meta.custody;
  return (
    <>
      <section>
        <h4>Host</h4>
        <dl className="kv">
          <dt>hostname</dt>
          <dd data-copy={o.meta.host.hostname} data-copy-label="hostname">
            {o.meta.host.hostname}
          </dd>
          <dt>os</dt>
          <dd>
            {o.meta.host.os_name} {o.meta.host.os_version}
          </dd>
          <dt>arch</dt>
          <dd>{o.meta.host.architecture}</dd>
          {o.meta.host.timezone_name && (
            <>
              <dt>timezone</dt>
              <dd>{o.meta.host.timezone_name}</dd>
            </>
          )}
          {o.meta.host.machine_id && (
            <>
              <dt>machine id</dt>
              <dd>{o.meta.host.machine_id}</dd>
            </>
          )}
        </dl>
      </section>

      <section>
        <h4>Contents</h4>
        <dl className="kv">
          <dt>events</dt>
          <dd>{o.counts.events.toLocaleString()}</dd>
          <dt>entities</dt>
          <dd>{o.counts.entities.toLocaleString()}</dd>
          <dt>relations</dt>
          <dd>{o.counts.edges.toLocaleString()}</dd>
          <dt>artifacts</dt>
          <dd>{o.counts.manifest_entries}</dd>
          <dt>blobs</dt>
          <dd>{o.counts.blobs}</dd>
          <dt>findings</dt>
          <dd>{findings.length}</dd>
        </dl>
      </section>

      {findings.length > 0 && (
        <section>
          <h4>Findings</h4>
          {findings.map((f, i) => (
            <div
              className={`finding sev-${f.severity}`}
              key={`${f.rule}-${i}`}
              onClick={() => onOpenFinding(f)}
              title={f.detail}
            >
              <b>{f.title}</b>
              <span className="finding-meta">
                {f.severity} · {f.rule}
              </span>
              <div className="dim">{f.detail}</div>
            </div>
          ))}
        </section>
      )}

      {manifest.length > 0 && (
        <section>
          <h4>Manifest</h4>
          {manifest.map((m, i) => (
            <div className={`manifest-row${m.error ? " gap" : ""}`} key={i}>
              <b>{m.source_path}</b>
              <div className="dim">
                {m.method}
                {m.events_emitted ? ` · ${m.events_emitted} events` : ""}
                {m.sha256 ? ` · ${m.sha256.slice(0, 12)}…` : ""}
                {m.error ? ` · ${m.error}` : ""}
              </div>
            </div>
          ))}
        </section>
      )}

      {o.gaps.length > 0 && (
        <section>
          <h4>Gaps in the evidence</h4>
          {o.gaps.map((g, i) => (
            <div className="gap" key={i}>
              <b>{g.sourcePath}</b>
              {g.method}: {g.error}
            </div>
          ))}
        </section>
      )}

      {c && (
        <section>
          <h4>Chain of custody</h4>
          <dl className="kv">
            <dt>collector</dt>
            <dd>{c.collector_version}</dd>
            <dt>ran as</dt>
            <dd>
              {c.run_as_user} {c.elevated ? "(elevated)" : "(not elevated)"}
            </dd>
            <dt>command</dt>
            <dd data-copy={c.command_line} data-copy-label="command">
              {c.command_line}
            </dd>
            {c.collector_sha256 && (
              <>
                <dt>tool sha256</dt>
                <dd data-copy={c.collector_sha256} data-copy-label="tool sha256">
                  {c.collector_sha256}
                </dd>
              </>
            )}
            <dt>wrote</dt>
            <dd>{c.files_written.join(", ") || "nothing"}</dd>
          </dl>
          {c.warnings.length > 0 && (
            <div style={{ marginTop: 8 }}>
              {c.warnings.map((w, i) => (
                <div className="gap" key={i}>
                  {w}
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {o.meta.content_digest && (
        <section>
          <h4>Integrity</h4>
          <dl className="kv">
            <dt>sha256</dt>
            <dd data-copy={o.meta.content_digest} data-copy-label="sha256">
              {o.meta.content_digest}
            </dd>
          </dl>
        </section>
      )}
    </>
  );
}

/* ----------------------------------------------------------------- event --- */

function EventPanel({
  d,
  onNavigate,
}: {
  d: EventDetail;
  onNavigate: (t: Target) => void;
}) {
  const reason = suspectReason(d.event.ts);
  return (
    <>
      <h3 data-copy={d.event.summary} data-copy-label="summary">
        {d.event.summary}
      </h3>

      <section>
        <dl className="kv">
          <dt>when</dt>
          <dd data-copy={d.event.iso} data-copy-label="when">
            {d.event.iso}
            {reason && <div className="note-suspect">{reason}</div>}
          </dd>
          <dt>precision</dt>
          <dd>{d.event.ts.precision}</dd>
          <dt>source</dt>
          <dd>
            {d.event.source} / {d.event.kind}
          </dd>
          {d.event.pid !== null && (
            <>
              <dt>pid</dt>
              <dd data-copy={String(d.event.pid)} data-copy-label="pid">
                {d.event.pid}
                {d.event.ppid !== null && ` (parent ${d.event.ppid})`}
              </dd>
            </>
          )}
          {d.event.image && (
            <>
              <dt>image</dt>
              <dd data-copy={d.event.image} data-copy-label="image">
                {d.event.image}
              </dd>
            </>
          )}
          {d.event.user && (
            <>
              <dt>user</dt>
              <dd data-copy={d.event.user} data-copy-label="user">
                {d.event.user}
              </dd>
            </>
          )}
          {d.event.path && (
            <>
              <dt>path</dt>
              <dd data-copy={d.event.path} data-copy-label="path">
                {d.event.path}
              </dd>
            </>
          )}
          {d.event.remote && (
            <>
              <dt>peer</dt>
              <dd data-copy={d.event.remote} data-copy-label="peer">
                {d.event.remote}
              </dd>
            </>
          )}
        </dl>
      </section>

      <section>
        <h4>Provenance</h4>
        {d.provenance ? (
          <dl className="kv">
            <dt>artifact</dt>
            <dd data-copy={d.provenance.source_path} data-copy-label="artifact">
              {d.provenance.source_path}
            </dd>
            <dt>acquired</dt>
            <dd>{d.provenance.method}</dd>
            <dt>size</dt>
            <dd>{bytes(d.provenance.size_bytes)}</dd>
            <dt>sha256</dt>
            <dd data-copy={d.provenance.sha256 ?? ""} data-copy-label="sha256">
              {d.provenance.sha256 ?? "not hashed"}
            </dd>
          </dl>
        ) : (
          <div className="dim">
            Observed directly from the live system, so there is no file to hash.
          </div>
        )}
      </section>

      {d.entity && (
        <section>
          <h4>Subject</h4>
          <div
            className="rel"
            onClick={() => onNavigate({ kind: "entity", key: d.entity!.key })}
          >
            <span className="rel-kind">{d.entity.kind}</span>
            <span className="rel-label">{d.entity.label}</span>
          </div>
        </section>
      )}

      {d.related.length > 0 && <Related items={d.related} onNavigate={onNavigate} />}

      {d.payload != null && (
        <section>
          <h4>Raw record</h4>
          <pre className="json">{JSON.stringify(d.payload, null, 2)}</pre>
        </section>
      )}
    </>
  );
}

/* ---------------------------------------------------------------- entity --- */

function EntityPanel({
  d,
  onNavigate,
  onFocusEntity,
}: {
  d: EntityDetail;
  onNavigate: (t: Target) => void;
  onFocusEntity: (key: string) => void;
}) {
  const a = (d.entity.attrs ?? {}) as Record<string, unknown>;
  const isProcess = d.entity.kind === "process";

  return (
    <>
      <h3 data-copy={d.entity.label} data-copy-label="process">
        {d.entity.label}
      </h3>
      <div className="subtitle">
        {d.entity.kind}
        {isProcess && a.session_id != null && ` \u2022 session ${a.session_id}`}
        {" \u2022 "}
        {d.entity.event_count} events
      </div>

      <div className="actions">
        <button onClick={() => onFocusEntity(d.entity.key)}>Filter timeline to this</button>
      </div>

      {typeof a.access_error === "string" && (
        <div className="gap">
          <b>Not fully inspected</b>
          {a.access_error}. Fields below that are blank were not readable, which is not
          the same as being empty.
        </div>
      )}

      {isProcess ? <ProcessFacts a={a} /> : <AttrFacts a={a} />}

      {d.related.length > 0 && <Related items={d.related} onNavigate={onNavigate} />}

      {d.recent.length > 0 && (
        <section>
          <h4>Events</h4>
          {d.recent.slice(0, 80).map((e: EventRow) => (
            <div
              className="rel"
              key={e.id}
              onClick={() => onNavigate({ kind: "event", id: e.id })}
            >
              <span className="rel-kind">{e.kind}</span>
              <span className="rel-label">{e.summary}</span>
            </div>
          ))}
          {d.recent.length > 80 && (
            <div className="dim">and {d.recent.length - 80} more</div>
          )}
        </section>
      )}
    </>
  );
}

/**
 * The process fields, in triage order.
 *
 * Command line first, because it is the single field that most often decides
 * whether a process is interesting, and because the executable name is the field
 * an adversary controls most cheaply.
 */
function ProcessFacts({ a }: { a: Record<string, unknown> }) {
  const s = (k: string) => (typeof a[k] === "string" ? (a[k] as string) : null);
  const n = (k: string) => (typeof a[k] === "number" ? (a[k] as number) : null);
  const b = (k: string) => (typeof a[k] === "boolean" ? (a[k] as boolean) : null);

  const cmd = s("command_line");
  return (
    <>
      <section>
        <h4>Execution</h4>
        <div className="field">
          <div className="field-label">command line</div>
          {cmd ? (
            <pre className="cmdline" data-copy={cmd} data-copy-label="command line">
              {cmd}
            </pre>
          ) : (
            <div className="dim">not readable</div>
          )}
        </div>
        <div className="field">
          <div className="field-label">image</div>
          {s("image_path") ? (
            <pre className="cmdline" data-copy={s("image_path") ?? ""} data-copy-label="image">
              {s("image_path")}
            </pre>
          ) : (
            <div className="dim">not readable</div>
          )}
        </div>
        {s("image_sha256") && (
          <div className="field">
            <div className="field-label">sha256</div>
            <pre className="cmdline" data-copy={s("image_sha256") ?? ""} data-copy-label="image sha256">
              {s("image_sha256")}
            </pre>
          </div>
        )}
      </section>

      <section>
        <h4>Identity</h4>
        <dl className="kv">
          <dt>user</dt>
          <dd data-copy={s("user") ?? ""} data-copy-label="user">
            {s("user") ?? <span className="dim">not readable</span>}
          </dd>
          <dt>elevated</dt>
          <dd>{yesNo(b("elevated"))}</dd>
          <dt>wow64</dt>
          <dd>{yesNo(b("wow64"))}</dd>
          <dt>session</dt>
          <dd>{n("session_id") ?? <span className="dim">unknown</span>}</dd>
        </dl>
      </section>

      <section>
        <h4>Runtime</h4>
        <dl className="kv">
          <dt>threads</dt>
          <dd>{n("thread_count") ?? <span className="dim">unknown</span>}</dd>
          <dt>handles</dt>
          <dd>{n("handle_count") ?? <span className="dim">unknown</span>}</dd>
          <dt>modules</dt>
          <dd>{n("module_count") ?? <span className="dim">unknown</span>}</dd>
        </dl>
      </section>
    </>
  );
}

/** Generic rendering for services, autoruns, drivers, files and endpoints. */
function AttrFacts({ a }: { a: Record<string, unknown> }) {
  const entries = Object.entries(a).filter(([, v]) => v !== null && typeof v !== "object");
  const nested = Object.entries(a).filter(([, v]) => v !== null && typeof v === "object");
  if (entries.length === 0 && nested.length === 0) return null;

  return (
    <section>
      <h4>Attributes</h4>
      <dl className="kv">
        {entries.map(([k, v]) => (
          <Fragment key={k}>
            <dt>{k.replace(/_/g, " ")}</dt>
            <dd>{String(v)}</dd>
          </Fragment>
        ))}
      </dl>
      {nested.map(([k, v]) => (
        <div key={k} style={{ marginTop: 8 }}>
          <div className="field-label">{k.replace(/_/g, " ")}</div>
          <pre className="json">{JSON.stringify(v, null, 2)}</pre>
        </div>
      ))}
    </section>
  );
}

function yesNo(v: boolean | null) {
  if (v === null) return <span className="dim">not readable</span>;
  return v ? "yes" : "no";
}

/* --------------------------------------------------------------- related --- */

/** Human wording for an edge, given which end the inspected entity is on. */
function relationLabel(kind: string, outgoing: boolean): string {
  switch (kind) {
    case "parent_of":
      return outgoing ? "child processes" : "parent process";
    case "executed_image":
      return outgoing ? "executable" : "executed by";
    case "loaded_module":
      return outgoing ? "loaded modules" : "loaded into";
    case "connected_to":
      return outgoing ? "network endpoints" : "used by";
    case "hosts_service":
      return outgoing ? "hosted process" : "services hosted here";
    default:
      return kind.replace(/_/g, " ");
  }
}

/** Triage order: lineage first, then network, then the long tail of modules. */
const RELATION_ORDER = [
  "parent process",
  "child processes",
  "executable",
  "network endpoints",
  "services hosted here",
  "hosted process",
  "executed by",
  "loaded into",
  "used by",
  "loaded modules",
];

function Related({
  items,
  onNavigate,
}: {
  items: RelatedEntity[];
  onNavigate: (t: Target) => void;
}) {
  const groups = new Map<string, RelatedEntity[]>();
  for (const r of items) {
    const label = relationLabel(r.kind, r.outgoing);
    const list = groups.get(label) ?? [];
    list.push(r);
    groups.set(label, list);
  }

  const ordered = [...groups.entries()].sort((x, y) => {
    const ix = RELATION_ORDER.indexOf(x[0]);
    const iy = RELATION_ORDER.indexOf(y[0]);
    return (ix < 0 ? 99 : ix) - (iy < 0 ? 99 : iy);
  });

  return (
    <section>
      <h4>Correlated</h4>
      {ordered.map(([label, list]) => (
        <RelationGroup key={label} label={label} list={list} onNavigate={onNavigate} />
      ))}
    </section>
  );
}

function RelationGroup({
  label,
  list,
  onNavigate,
}: {
  label: string;
  list: RelatedEntity[];
  onNavigate: (t: Target) => void;
}) {
  // Long groups start collapsed. A process with two hundred loaded modules would
  // otherwise bury the one parent edge that explains where it came from.
  const long = list.length > 8;
  const [open, setOpen] = useState(!long);
  const shown = open ? list : list.slice(0, 0);

  return (
    <div className="rel-group">
      <div className="rel-head" onClick={() => setOpen(!open)}>
        <span className="twisty">{open ? "\u25bc" : "\u25b6"}</span>
        {label}
        <span className="rel-n">{list.length}</span>
      </div>
      {shown.slice(0, 200).map((r: RelatedEntity) => (
        <div
          className="rel"
          key={r.entity.key}
          onClick={() => onNavigate({ kind: "entity", key: r.entity.key })}
          title={r.entity.key}
        >
          <span className="rel-label">{r.entity.label || r.entity.key}</span>
        </div>
      ))}
      {open && shown.length > 200 && (
        <div className="dim">and {shown.length - 200} more</div>
      )}
    </div>
  );
}

export type { Target };
