//! The `.tpv` on-disk schema.
//!
//! The container is a plain SQLite database. That is a deliberate forensic
//! choice: an analyst without TreePView can still open a case in any SQLite
//! browser and query it, and enum values are stored as readable text rather than
//! opaque integers so those queries make sense without our source code. The cost
//! is a few bytes per row, which zstd on the payload side more than repays.

/// `TPV1` in ASCII, stored in SQLite's `application_id` header field so the file
/// type is identifiable without parsing any tables.
pub const APPLICATION_ID: i32 = 0x5450_5631;

/// Bumped when tables are added. Older readers ignore unknown tables.
pub const SCHEMA_VERSION: u32 = 2;

/// Blob chunk size. Large enough that compression finds real redundancy in a
/// minidump, small enough that seeking into a multi-gigabyte physical memory
/// image does not force decompressing hundreds of megabytes.
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Compression level. Level 9 sits near the knee of the curve for the JSON and
/// minidump content that dominates a case; higher levels cost collection time on
/// a host we want to leave quickly.
pub const ZSTD_LEVEL: i32 = 9;

pub const DDL: &str = r#"
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

-- Deduplicated nodes of the case graph. `key` is the natural key, so the same
-- binary seen in prefetch, in $MFT and as a running image collapses to one row.
CREATE TABLE entities (
    id    INTEGER PRIMARY KEY,
    kind  TEXT NOT NULL,
    key   TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    attrs BLOB
);
CREATE INDEX idx_entities_kind ON entities(kind);

-- Full source detail, zstd-compressed and deduplicated by content hash. Event
-- log records repeat heavily, so this is where most of the size reduction lives.
CREATE TABLE payloads (
    id      INTEGER PRIMARY KEY,
    sha256  TEXT NOT NULL UNIQUE,
    raw_len INTEGER NOT NULL,
    z       BLOB NOT NULL
);

-- The unified timeline. The denormalized columns exist so that filtering by PID,
-- image, path or peer stays an indexed query instead of a payload scan.
CREATE TABLE events (
    id            INTEGER PRIMARY KEY,
    ts_utc_ns     INTEGER NOT NULL,
    ts_precision  TEXT NOT NULL,
    ts_tz_source  TEXT NOT NULL,
    ts_flags      INTEGER NOT NULL DEFAULT 0,
    ts_end_utc_ns INTEGER,
    source        TEXT NOT NULL,
    kind          TEXT NOT NULL,
    entity_id     INTEGER REFERENCES entities(id),
    pid           INTEGER,
    ppid          INTEGER,
    image         TEXT,
    user          TEXT,
    path          TEXT,
    remote        TEXT,
    -- Windows Event ID / Sysmon ID. Null on live snapshots that have no log id.
    log_id        INTEGER,
    summary       TEXT NOT NULL,
    payload_id    INTEGER REFERENCES payloads(id)
);
CREATE INDEX idx_events_ts        ON events(ts_utc_ns);
CREATE INDEX idx_events_pid_ts    ON events(pid, ts_utc_ns);
CREATE INDEX idx_events_source_ts ON events(source, ts_utc_ns);
CREATE INDEX idx_events_kind_ts   ON events(kind, ts_utc_ns);
CREATE INDEX idx_events_entity    ON events(entity_id);
CREATE INDEX idx_events_log_id    ON events(log_id) WHERE log_id IS NOT NULL;
-- Timestamps that were clamped or absent are themselves evidence, so they get
-- their own partial index rather than requiring a full scan to find.
CREATE INDEX idx_events_ts_flags  ON events(ts_flags) WHERE ts_flags != 0;

-- External-content FTS: the text lives in `events`, and the index is built once
-- at finalize rather than maintained row by row during collection.
--
-- The stock unicode61 tokenizer is used deliberately. Adding path and address
-- punctuation to `tokenchars` looks right but makes things worse: it turns
-- `203.0.113.7:443` into one indivisible token, so searching for the address
-- without the port finds nothing. Splitting on punctuation and letting the query
-- side quote the analyst's input as a phrase gets both cases right, because
-- `evil.exe` then matches inside `C:\Users\Public\evil.exe` and `203.0.113.7`
-- matches inside `203.0.113.7:443`.
CREATE VIRTUAL TABLE events_fts USING fts5(
    summary, image, path, remote, user,
    content='events', content_rowid='id'
);

CREATE TABLE edges (
    id      INTEGER PRIMARY KEY,
    from_id INTEGER NOT NULL REFERENCES entities(id),
    to_id   INTEGER NOT NULL REFERENCES entities(id),
    kind    TEXT NOT NULL,
    source  TEXT NOT NULL,
    UNIQUE(from_id, to_id, kind, source)
);
CREATE INDEX idx_edges_from ON edges(from_id, kind);
CREATE INDEX idx_edges_to   ON edges(to_id, kind);

-- Large binaries: minidumps, hive copies, raw memory. Stored as independently
-- compressed chunks so the viewer can seek without inflating the whole thing.
CREATE TABLE blobs (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL,
    raw_len     INTEGER NOT NULL,
    sha256      TEXT NOT NULL,
    chunk_size  INTEGER NOT NULL,
    chunk_count INTEGER NOT NULL,
    entity_id   INTEGER REFERENCES entities(id)
);

CREATE TABLE blob_chunks (
    blob_id INTEGER NOT NULL REFERENCES blobs(id),
    idx     INTEGER NOT NULL,
    raw_len INTEGER NOT NULL,
    z       BLOB NOT NULL,
    PRIMARY KEY (blob_id, idx)
) WITHOUT ROWID;

-- Chain of custody: every source artifact, how it was reached, and its hash.
-- Failures are rows too, because an artifact that could not be read is a fact
-- about the case rather than an absence.
CREATE TABLE manifest (
    id              INTEGER PRIMARY KEY,
    source_path     TEXT NOT NULL,
    method          TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    sha256          TEXT,
    started_utc_ns  INTEGER NOT NULL,
    finished_utc_ns INTEGER NOT NULL,
    events_emitted  INTEGER NOT NULL DEFAULT 0,
    error           TEXT
);

-- Derived, regenerable, and deletable without touching evidence.
CREATE TABLE findings (
    id               INTEGER PRIMARY KEY,
    rule             TEXT NOT NULL,
    severity         TEXT NOT NULL,
    confidence       TEXT NOT NULL,
    title            TEXT NOT NULL,
    detail           TEXT NOT NULL,
    entity_id        INTEGER REFERENCES entities(id),
    generated_utc_ns INTEGER NOT NULL
);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_rule     ON findings(rule);

CREATE TABLE finding_evidence (
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    event_id   INTEGER NOT NULL REFERENCES events(id),
    PRIMARY KEY (finding_id, event_id)
) WITHOUT ROWID;
CREATE INDEX idx_finding_evidence_event ON finding_evidence(event_id);

-- Derived process forest. Regenerable from events; not evidence.
-- Identity is the ULID, never the PID: Windows recycles PIDs.
CREATE TABLE process_instance (
    id              TEXT PRIMARY KEY,
    pid             INTEGER NOT NULL,
    start_utc_ns    INTEGER,
    exit_utc_ns     INTEGER,
    image_path      TEXT,
    user_sid        TEXT,
    entity_id       INTEGER REFERENCES entities(id),
    unlinked        INTEGER NOT NULL DEFAULT 0,
    source_set      TEXT NOT NULL,
    parent_edge     TEXT NOT NULL,
    claimed_ppid    INTEGER,
    parent_id       TEXT REFERENCES process_instance(id),
    indicators      TEXT NOT NULL DEFAULT '[]',
    event_ids       TEXT NOT NULL DEFAULT '[]',
    start_exact     INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_pi_pid_start ON process_instance(pid, start_utc_ns);

CREATE TABLE process_field (
    instance_id     TEXT NOT NULL REFERENCES process_instance(id),
    field           TEXT NOT NULL,
    value           TEXT,
    source          TEXT NOT NULL,
    confidence      TEXT NOT NULL,
    observed_utc_ns INTEGER NOT NULL,
    PRIMARY KEY (instance_id, field, source)
);
"#;

// Metadata keys. Named constants because both the writer and the reader must
// agree on them exactly, and a typo would only surface at read time.
pub const META_FORMAT_VERSION: &str = "format_version";
pub const META_CASE_ID: &str = "case_id";
pub const META_TOOL_VERSION: &str = "tool_version";
pub const META_CREATED_NS: &str = "created_utc_ns";
pub const META_HOST: &str = "host_info";
pub const META_CLOCK: &str = "reference_clock";
pub const META_PROFILE: &str = "collection_profile";
pub const META_CUSTODY: &str = "custody";
pub const META_FINALIZED: &str = "finalized";
pub const META_CONTENT_DIGEST: &str = "content_digest";
/// Nanoseconds. How far apart two stamps of the same PID may be and still
/// count as one instance. Recorded on the case so reimport is reproducible.
pub const META_MATCH_TOLERANCE_NS: &str = "process_match_tolerance_ns";
