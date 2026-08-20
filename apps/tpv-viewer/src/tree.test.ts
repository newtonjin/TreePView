import { describe, expect, it } from "vitest";
import type { ProcessNode } from "./api";
import {
  andPredicates,
  countForest,
  flattenForest,
  pathTo,
  rangePredicate,
  textPredicate,
} from "./tree";

function proc(
  label: string,
  pid: number,
  startNs: number | null,
  children: ProcessNode[] = [],
  extra: Partial<ProcessNode> = {},
): ProcessNode {
  return {
    entity_id: pid,
    key: `proc:${pid}:${startNs ?? "unknown"}`,
    instance_id: `01TEST${pid}`,
    label,
    pid,
    started:
      startNs === null ? null : { ns: startNs, iso: `t+${startNs}`, exact: true },
    image: `C:\\Windows\\${label}`,
    command_line: `${label}`,
    user: "TARGET\\victim",
    elevated: false,
    access_error: null,
    event_count: 1,
    first_event_ns: startNs,
    last_event_ns: startNs,
    max_severity: null,
    parent_edge: "root",
    claimed_ppid: null,
    source_set: [],
    indicators: [],
    related_logs: [],
    related_logs_omitted: 0,
    children,
    ...extra,
  };
}

/** A small but realistically shaped host: deep, wide, and with an orphan. */
function forest(): ProcessNode[] {
  return [
    proc("System", 4, 100, [
      proc("smss.exe", 300, 200, [proc("csrss.exe", 400, 300)]),
    ]),
    proc("wininit.exe", 500, 400, [
      proc("services.exe", 600, 500, [
        proc("svchost.exe", 700, 600),
        proc("svchost.exe", 800, 700),
        proc("spoolsv.exe", 900, 800),
      ]),
    ]),
    proc("explorer.exe", 1000, 900, [
      proc("winword.exe", 1100, 1000, [
        proc("powershell.exe", 1200, 1100, [proc("evil.exe", 1300, 1200)]),
      ]),
    ]),
  ];
}

describe("flattenForest", () => {
  it("shows every process when nothing is collapsed", () => {
    const f = forest();
    const rows = flattenForest(f, new Set());
    expect(rows.length).toBe(countForest(f));
    expect(rows.length).toBe(12);
  });

  it("indents each generation one level deeper", () => {
    const rows = flattenForest(forest(), new Set());
    const byLabel = new Map(rows.map((r) => [r.node.label, r.depth]));
    expect(byLabel.get("System")).toBe(0);
    expect(byLabel.get("smss.exe")).toBe(1);
    expect(byLabel.get("csrss.exe")).toBe(2);
    expect(byLabel.get("evil.exe")).toBe(3);
  });

  it("hides only the descendants of a collapsed node", () => {
    const rows = flattenForest(forest(), new Set(["proc:600:500"]));
    const labels = rows.map((r) => r.node.label);
    expect(labels).toContain("services.exe");
    expect(labels).not.toContain("svchost.exe");
    expect(labels).not.toContain("spoolsv.exe");
    // Unrelated branches are untouched.
    expect(labels).toContain("evil.exe");
  });

  it("marks a collapsed node as still having children", () => {
    const rows = flattenForest(forest(), new Set(["proc:600:500"]));
    const services = rows.find((r) => r.node.label === "services.exe")!;
    expect(services.hasChildren).toBe(true);
    expect(services.expanded).toBe(false);
  });

  it("keeps the ancestors of a match so the lineage stays readable", () => {
    const rows = flattenForest(forest(), new Set(), textPredicate("evil"));
    expect(rows.map((r) => r.node.label)).toEqual([
      "explorer.exe",
      "winword.exe",
      "powershell.exe",
      "evil.exe",
    ]);
  });

  it("distinguishes a match from an ancestor shown for context", () => {
    const rows = flattenForest(forest(), new Set(), textPredicate("evil"));
    expect(rows.find((r) => r.node.label === "evil.exe")!.contextOnly).toBe(false);
    expect(rows.find((r) => r.node.label === "winword.exe")!.contextOnly).toBe(true);
  });

  it("searches the command line, not just the image name", () => {
    const f = forest();
    f[2].children[0].command_line = "winword.exe /q /n http://c2.example/doc";
    const rows = flattenForest(f, new Set(), textPredicate("c2.example"));
    expect(rows.map((r) => r.node.label)).toEqual(["explorer.exe", "winword.exe"]);
  });

  it("returns nothing when the filter matches nothing", () => {
    expect(flattenForest(forest(), new Set(), textPredicate("zzz"))).toEqual([]);
  });

  it("terminates on a parent cycle instead of recursing forever", () => {
    const a = proc("a.exe", 1, 100);
    const b = proc("b.exe", 2, 200);
    a.children.push(b);
    b.children.push(a);
    // A cycle cannot arise from a well-formed collection, but a case file is
    // untrusted input and the viewer must not hang on one.
    expect(() => flattenForest([a], new Set(), textPredicate("zzz"))).not.toThrow();
  });

  it("nests Event Log rows under the process they describe", () => {
    const f = [
      proc("powershell.exe", 1200, 1100, [], {
        related_logs: [
          {
            event_id: 9,
            log_id: 4688,
            kind: "process_start",
            source: "evtx",
            iso: "t+1100",
            summary: "[4688] powershell.exe started",
            ts_ns: 1100,
          },
        ],
        related_logs_omitted: 0,
      }),
    ];
    const rows = flattenForest(f, new Set());
    expect(rows).toHaveLength(2);
    expect(rows[0].log).toBeUndefined();
    expect(rows[0].hasChildren).toBe(true);
    expect(rows[1].log?.log_id).toBe(4688);
    expect(rows[1].depth).toBe(1);
  });

  it("finds a process by the Event ID hanging on its branch", () => {
    const f = [
      proc("explorer.exe", 1000, 900, [
        proc("powershell.exe", 1200, 1100, [], {
          related_logs: [
            {
              event_id: 9,
              log_id: 4688,
              kind: "process_start",
              source: "evtx",
              iso: "t+1100",
              summary: "[4688] powershell.exe started",
              ts_ns: 1100,
            },
          ],
        }),
      ]),
    ];
    const rows = flattenForest(f, new Set(), textPredicate("4688"));
    expect(rows.map((r) => r.node.label)).toEqual(["explorer.exe", "powershell.exe", "powershell.exe"]);
    expect(rows[2].log?.log_id).toBe(4688);
    expect(rows[0].contextOnly).toBe(true);
    expect(rows[1].contextOnly).toBe(false);
  });
});

describe("rangePredicate", () => {
  it("keeps processes that started inside the window", () => {
    const rows = flattenForest(
      forest(),
      new Set(),
      andPredicates(rangePredicate(1000, 1300)),
    );
    // winword, powershell and evil started in range; explorer is kept as their
    // ancestor.
    expect(rows.map((r) => r.node.label)).toEqual([
      "explorer.exe",
      "winword.exe",
      "powershell.exe",
      "evil.exe",
    ]);
    expect(rows[0].contextOnly).toBe(true);
  });

  it("keeps a process whose correlated Event ID falls inside the window", () => {
    const f = [
      proc("powershell.exe", 1200, 100, [], {
        related_logs: [
          {
            event_id: 9,
            log_id: 4688,
            kind: "process_start",
            source: "evtx",
            iso: "t+1100",
            summary: "[4688] powershell.exe started",
            ts_ns: 1100,
          },
        ],
      }),
    ];
    const rows = flattenForest(f, new Set(), rangePredicate(1000, 1300));
    expect(rows).toHaveLength(2);
    expect(rows[0].contextOnly).toBe(false);
    expect(rows[1].log?.log_id).toBe(4688);
  });
});

describe("pathTo", () => {
  it("returns the ancestors needed to reveal a node", () => {
    expect(pathTo(forest(), "proc:1300:1200").map((n) => n.label)).toEqual([
      "explorer.exe",
      "winword.exe",
      "powershell.exe",
      "evil.exe",
    ]);
  });

  it("returns nothing for a key that is not in the forest", () => {
    expect(pathTo(forest(), "proc:9999:0")).toEqual([]);
  });
});
