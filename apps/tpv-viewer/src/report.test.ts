import { describe, expect, it } from "vitest";
import type { EventRow, ProcessNode } from "./api";
import { caseBriefMarkdown, eventFields, formatFields, processFields } from "./report";

function proc(extra: Partial<ProcessNode> = {}): ProcessNode {
  return {
    entity_id: 6660,
    key: "proc:6660:1",
    label: "svch0st.exe",
    pid: 6660,
    started: { ns: 1, iso: "2026-08-18T14:22:01.123Z", exact: true },
    image: "C:\\ProgramData\\svch0st.exe",
    command_line: "C:\\ProgramData\\svch0st.exe -c 203.0.113.7:443",
    user: "TARGET\\victim",
    elevated: false,
    access_error: null,
    event_count: 4,
    first_event_ns: 1,
    last_event_ns: 1,
    max_severity: "high",
    children: [],
    ...extra,
  };
}

describe("processFields", () => {
  it("emits a labeled block an analyst can paste into a report", () => {
    const text = formatFields(processFields(proc()));
    expect(text).toBe(
      [
        "Process: svch0st.exe",
        "PID: 6660",
        "User: TARGET\\victim",
        "Image: C:\\ProgramData\\svch0st.exe",
        "Command line: C:\\ProgramData\\svch0st.exe -c 203.0.113.7:443",
        "Started: 2026-08-18T14:22:01.123Z",
        "",
      ].join("\n"),
    );
  });

  it("marks elevation on the user line rather than as a separate claim", () => {
    const user = processFields(proc({ elevated: true })).find((f) => f.label === "User");
    expect(user?.value).toBe("TARGET\\victim (elevated)");
  });

  it("omits blank fields so a denied process does not paste empty lines", () => {
    const text = formatFields(
      processFields(
        proc({
          command_line: null,
          image: null,
          user: null,
          access_error: "access denied",
        }),
      ),
    );
    expect(text).toContain("Not inspected: access denied");
    expect(text).not.toContain("Command line:");
    expect(text).not.toContain("Image:");
  });
});

describe("eventFields", () => {
  it("keeps time, process and summary in a document-ready order", () => {
    const row: EventRow = {
      id: 1,
      ts: { utc_ns: 1, precision: "millisecond", tz_source: "native_utc", flags: 0 },
      iso: "2026-08-18T14:22:01.123Z",
      ts_end_utc_ns: null,
      source: "live",
      kind: "process_start",
      entity_key: "proc:6660:1",
      pid: 6660,
      ppid: 1000,
      image: "C:\\ProgramData\\svch0st.exe",
      user: "TARGET\\victim",
      path: null,
      remote: "203.0.113.7:443",
      log_id: 3,
      summary: "svch0st.exe connected outbound",
      has_payload: false,
    };
    const text = formatFields(eventFields(row));
    expect(text.startsWith("Time (UTC): 2026-08-18T14:22:01.123Z\n")).toBe(true);
    expect(text).toContain("PID: 6660");
    expect(text).toContain("Parent PID: 1000");
    expect(text).toContain("Event ID: 3");
    expect(text).toContain("Remote: 203.0.113.7:443");
    expect(text).toContain("Summary: svch0st.exe connected outbound");
  });
});

describe("caseBriefMarkdown", () => {
  it("summarizes host, counts and gaps for a one-page report", () => {
    const md = caseBriefMarkdown({
      path: "x.tpv",
      meta: {
        format_version: 1,
        case_id: "c",
        tool_version: "tpv/test",
        created_utc_ns: 1,
        host: {
          hostname: "BOX",
          os_name: "Windows",
          os_version: "11",
          architecture: "x86_64",
          domain: null,
          machine_id: null,
          timezone_name: null,
          utc_offset_minutes: null,
          boot_time: null,
        },
        clock: {
          host_utc: { utc_ns: 1, precision: "second", tz_source: "native_utc", flags: 0 },
          monotonic_uptime_ms: null,
        },
        profile: {},
        custody: null,
        finalized: true,
        content_digest: "abc",
      },
      counts: { events: 3, entities: 1, edges: 0, blobs: 0, manifest_entries: 1, findings: 0 },
      span: null,
      sources: [],
      kinds: [],
      gaps: [{ sourcePath: "Security.evtx", method: "win32_file", error: "access denied" }],
    });
    expect(md).toContain("BOX");
    expect(md).toContain("Security.evtx");
    expect(md).toContain("access denied");
  });
});
