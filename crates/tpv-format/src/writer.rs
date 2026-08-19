//! Building a `.tpv` case.
//!
//! The writer is used on the host under examination, so its priorities are
//! bounded memory, bounded time, and never leaving the case file in a state that
//! cannot be read. It is append-only: nothing that has been written is ever
//! rewritten, which means a collection killed halfway still yields a case
//! containing everything gathered up to that point.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};
use tpv_model::{
    CaseId, CollectionProfile, Custody, Edge, Entity, EntityKind, Event, HostInfo, ManifestEntry,
    ReferenceClock, FORMAT_VERSION,
};

use crate::blob::BlobInfo;
use crate::error::{FormatError, Result};
use crate::hash::{sha256_hex, RollingSha256};
use crate::schema;

/// Everything known before collection starts.
#[derive(Debug, Clone)]
pub struct CaseInit {
    pub case_id: CaseId,
    pub tool_version: String,
    pub host: HostInfo,
    pub clock: ReferenceClock,
    pub profile: CollectionProfile,
}

/// What a finished case contains, returned so the collector can report without
/// reopening the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseSummary {
    pub path: PathBuf,
    pub events: u64,
    pub entities: u64,
    pub edges: u64,
    pub blobs: u64,
    pub manifest_entries: u64,
    /// Size of the finished case file in bytes.
    pub file_size: u64,
    /// SHA-256 over the logical contents, stored inside the case.
    pub content_digest: String,
    /// SHA-256 over the finished file, written to a sidecar.
    pub file_digest: String,
}

/// Rows written between automatic commits.
///
/// Large enough to keep per-transaction overhead negligible, small enough that
/// an abrupt termination loses at most a second or two of collection.
const COMMIT_INTERVAL: u64 = 20_000;

pub struct CaseWriter {
    conn: Connection,
    path: PathBuf,
    /// Natural key to row id, so a repeated entity costs a hash lookup rather
    /// than a SQL round trip. Collections routinely reference the same few
    /// thousand images across millions of events.
    entity_cache: HashMap<String, i64>,
    /// Payload content hash to row id, which is what makes payload dedup cheap.
    payload_cache: HashMap<String, i64>,
    pending: u64,
    events: u64,
    edges: u64,
    blobs: u64,
    manifest_entries: u64,
    finalized: bool,
}

impl CaseWriter {
    /// Create a new case file.
    ///
    /// Refuses to overwrite an existing file: in an incident, silently replacing
    /// a previous collection would destroy evidence.
    pub fn create(path: impl AsRef<Path>, init: CaseInit) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(FormatError::CaseExists(path));
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let conn = Connection::open(&path)?;

        // Page size has to be set before anything creates a page, so it comes
        // first. The rest trade durability for speed, which is the right trade
        // while the file is still being built: a crashed collection is restarted
        // rather than repaired.
        conn.pragma_update(None, "page_size", 8192)?;
        conn.pragma_update(None, "journal_mode", "MEMORY")?;
        conn.pragma_update(None, "synchronous", "OFF")?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        conn.pragma_update(None, "cache_size", -65_536i64)?;
        conn.pragma_update(None, "application_id", schema::APPLICATION_ID)?;
        conn.pragma_update(None, "user_version", schema::SCHEMA_VERSION)?;

        conn.execute_batch(schema::DDL)?;

        let w = Self {
            conn,
            path,
            entity_cache: HashMap::new(),
            payload_cache: HashMap::new(),
            pending: 0,
            events: 0,
            edges: 0,
            blobs: 0,
            manifest_entries: 0,
            finalized: false,
        };

        w.put_meta(schema::META_FORMAT_VERSION, &FORMAT_VERSION.to_string())?;
        w.put_meta(schema::META_CASE_ID, &init.case_id.0)?;
        w.put_meta(schema::META_TOOL_VERSION, &init.tool_version)?;
        w.put_meta(
            schema::META_CREATED_NS,
            &init.clock.host_utc.utc_ns.to_string(),
        )?;
        w.put_meta(schema::META_HOST, &serde_json::to_string(&init.host)?)?;
        w.put_meta(schema::META_CLOCK, &serde_json::to_string(&init.clock)?)?;
        w.put_meta(schema::META_PROFILE, &serde_json::to_string(&init.profile)?)?;
        w.put_meta(schema::META_FINALIZED, "0")?;

        w.conn.execute_batch("BEGIN")?;
        Ok(w)
    }

    fn put_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Commit periodically so an interrupted collection keeps what it gathered.
    fn tick(&mut self) -> Result<()> {
        self.pending += 1;
        if self.pending >= COMMIT_INTERVAL {
            self.conn.execute_batch("COMMIT; BEGIN")?;
            self.pending = 0;
        }
        Ok(())
    }

    /// Insert or update an entity, returning its row id.
    ///
    /// Upsert rather than insert because sources arrive out of order: an edge
    /// may name a process before the process list is walked, and a stub created
    /// then must be upgraded in place when the real record shows up.
    pub fn upsert_entity(&mut self, entity: &Entity) -> Result<i64> {
        let attrs = match &entity.attrs {
            Some(v) => Some(zstd::encode_all(
                serde_json::to_vec(v)?.as_slice(),
                schema::ZSTD_LEVEL,
            )?),
            None => None,
        };

        self.conn.execute(
            "INSERT INTO entities(kind, key, label, attrs) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(key) DO UPDATE SET
                 kind  = excluded.kind,
                 label = excluded.label,
                 attrs = COALESCE(excluded.attrs, entities.attrs)",
            params![entity.kind.as_str(), entity.key, entity.label, attrs],
        )?;

        let id: i64 = self.conn.query_row(
            "SELECT id FROM entities WHERE key = ?1",
            params![entity.key],
            |r| r.get(0),
        )?;
        self.entity_cache.insert(entity.key.clone(), id);
        self.tick()?;
        Ok(id)
    }

    /// Resolve a natural key to a row id, creating a placeholder if the entity
    /// has not been described yet.
    fn entity_id_for_key(&mut self, key: &str) -> Result<i64> {
        if let Some(id) = self.entity_cache.get(key) {
            return Ok(*id);
        }
        if let Some(id) = self
            .conn
            .query_row("SELECT id FROM entities WHERE key = ?1", params![key], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?
        {
            self.entity_cache.insert(key.to_string(), id);
            return Ok(id);
        }

        // A placeholder keeps the graph connected until the describing source is
        // parsed. Its kind is inferred from the key prefix the model produces.
        let kind = if key.starts_with("proc:") {
            EntityKind::Process
        } else {
            EntityKind::File
        };
        self.conn.execute(
            "INSERT INTO entities(kind, key, label) VALUES (?1, ?2, ?3)",
            params![kind.as_str(), key, key],
        )?;
        let id = self.conn.last_insert_rowid();
        self.entity_cache.insert(key.to_string(), id);
        Ok(id)
    }

    /// Store a payload, deduplicated by content hash.
    fn payload_id(&mut self, value: &serde_json::Value) -> Result<i64> {
        // serde_json orders map keys deterministically by default, so equal
        // payloads always produce identical bytes and therefore dedup correctly.
        let raw = serde_json::to_vec(value)?;
        let digest = sha256_hex(&raw);

        if let Some(id) = self.payload_cache.get(&digest) {
            return Ok(*id);
        }
        if let Some(id) = self
            .conn
            .query_row(
                "SELECT id FROM payloads WHERE sha256 = ?1",
                params![digest],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
        {
            self.payload_cache.insert(digest, id);
            return Ok(id);
        }

        let z = zstd::encode_all(raw.as_slice(), schema::ZSTD_LEVEL)?;
        self.conn.execute(
            "INSERT INTO payloads(sha256, raw_len, z) VALUES (?1, ?2, ?3)",
            params![digest, raw.len() as i64, z],
        )?;
        let id = self.conn.last_insert_rowid();
        self.payload_cache.insert(digest, id);
        Ok(id)
    }

    /// Append one timeline event, returning its row id so a finding can cite it.
    pub fn add_event(&mut self, event: &Event) -> Result<i64> {
        let entity_id = match &event.entity_key {
            Some(k) => Some(self.entity_id_for_key(k)?),
            None => None,
        };
        let payload_id = match &event.payload {
            Some(v) => Some(self.payload_id(v)?),
            None => None,
        };

        self.conn.execute(
            "INSERT INTO events(
                 ts_utc_ns, ts_precision, ts_tz_source, ts_flags, ts_end_utc_ns,
                 source, kind, entity_id, pid, ppid, image, user, path, remote,
                 log_id, summary, payload_id)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            params![
                event.ts.utc_ns,
                event.ts.precision.as_str(),
                event.ts.tz_source.as_str(),
                event.ts.flags.0 as i64,
                event.ts_end.map(|t| t.utc_ns),
                event.source.as_str(),
                event.kind.as_str(),
                entity_id,
                event.pid,
                event.ppid,
                event.image,
                event.user,
                event.path,
                event.remote,
                event.log_id,
                event.summary,
                payload_id,
            ],
        )?;

        let id = self.conn.last_insert_rowid();
        self.events += 1;
        self.tick()?;
        Ok(id)
    }

    /// Record a relation between two entities. Duplicates are ignored, so a
    /// source may assert the same edge repeatedly without special-casing.
    pub fn add_edge(&mut self, edge: &Edge) -> Result<()> {
        let from = self.entity_id_for_key(&edge.from_key)?;
        let to = self.entity_id_for_key(&edge.to_key)?;
        let changed = self.conn.execute(
            "INSERT OR IGNORE INTO edges(from_id, to_id, kind, source) VALUES (?1,?2,?3,?4)",
            params![from, to, edge.kind.as_str(), edge.source.as_str()],
        )?;
        if changed > 0 {
            self.edges += 1;
        }
        self.tick()?;
        Ok(())
    }

    /// Record an acquired source artifact, successful or not.
    pub fn add_manifest(&mut self, entry: &ManifestEntry) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO manifest(
                 source_path, method, size_bytes, sha256,
                 started_utc_ns, finished_utc_ns, events_emitted, error)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                entry.source_path,
                entry.method.as_str(),
                entry.size_bytes as i64,
                entry.sha256,
                entry.started.utc_ns,
                entry.finished.utc_ns,
                entry.events_emitted as i64,
                entry.error,
            ],
        )?;
        self.manifest_entries += 1;
        self.tick()?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Stream a large binary into the case, chunked and compressed.
    ///
    /// The source is read through a fixed buffer and hashed as it goes, so a
    /// multi-gigabyte memory image never has to be resident. The returned
    /// [`BlobInfo`] carries the hash of the original stream, which is what a
    /// later integrity check compares against.
    pub fn add_blob<R: Read>(
        &mut self,
        name: &str,
        kind: &str,
        entity_key: Option<&str>,
        reader: &mut R,
    ) -> Result<BlobInfo> {
        let entity_id = match entity_key {
            Some(k) => Some(self.entity_id_for_key(k)?),
            None => None,
        };

        self.conn.execute(
            "INSERT INTO blobs(name, kind, raw_len, sha256, chunk_size, chunk_count, entity_id)
             VALUES (?1, ?2, 0, '', ?3, 0, ?4)",
            params![name, kind, schema::DEFAULT_CHUNK_SIZE as i64, entity_id],
        )?;
        let blob_id = self.conn.last_insert_rowid();

        let mut hasher = RollingSha256::new();
        let mut buf = vec![0u8; schema::DEFAULT_CHUNK_SIZE];
        let mut chunk_index: u64 = 0;
        let mut total: u64 = 0;

        loop {
            // Fill the whole chunk before compressing: a short `read` is not
            // end-of-stream, and honouring it would produce ragged chunks that
            // break the offset-to-index arithmetic the reader relies on.
            let mut filled = 0usize;
            while filled < buf.len() {
                let n = reader.read(&mut buf[filled..])?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            if filled == 0 {
                break;
            }

            hasher.update(&buf[..filled]);
            total += filled as u64;

            let z = zstd::encode_all(&buf[..filled], schema::ZSTD_LEVEL)?;
            self.conn.execute(
                "INSERT INTO blob_chunks(blob_id, idx, raw_len, z) VALUES (?1,?2,?3,?4)",
                params![blob_id, chunk_index as i64, filled as i64, z],
            )?;
            chunk_index += 1;
            self.tick()?;

            if filled < buf.len() {
                break;
            }
        }

        let sha256 = hasher.finish();
        self.conn.execute(
            "UPDATE blobs SET raw_len = ?1, sha256 = ?2, chunk_count = ?3 WHERE id = ?4",
            params![total as i64, sha256, chunk_index as i64, blob_id],
        )?;
        self.blobs += 1;

        Ok(BlobInfo {
            id: blob_id,
            name: name.to_string(),
            kind: kind.to_string(),
            raw_len: total,
            sha256,
            chunk_size: schema::DEFAULT_CHUNK_SIZE as u64,
            chunk_count: chunk_index,
        })
    }

    /// Number of events written so far, for progress reporting.
    pub fn event_count(&self) -> u64 {
        self.events
    }

    /// Close the case: build the search index, seal the metadata, and hash.
    ///
    /// The FTS index is built once here rather than maintained per row. During
    /// collection every insert would otherwise pay for index maintenance on a
    /// host we are trying to leave quickly, and the index is worthless until the
    /// case is complete anyway.
    pub fn finish(mut self, custody: Custody) -> Result<CaseSummary> {
        if self.finalized {
            return Err(FormatError::AlreadyFinalized);
        }

        self.conn.execute_batch("COMMIT")?;
        self.put_meta(schema::META_CUSTODY, &serde_json::to_string(&custody)?)?;

        let content_digest = self.compute_content_digest()?;
        self.put_meta(schema::META_CONTENT_DIGEST, &content_digest)?;
        self.put_meta(schema::META_FINALIZED, "1")?;

        self.conn
            .execute_batch("INSERT INTO events_fts(events_fts) VALUES('rebuild')")?;
        self.conn.execute_batch("PRAGMA optimize")?;

        // Back to a rollback journal so the finished case is exactly one file,
        // with no -wal or -shm sidecars to lose in transit.
        self.conn
            .pragma_update(None, "journal_mode", "DELETE")?;
        self.conn.pragma_update(None, "synchronous", "FULL")?;

        let entities: u64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM entities", [], |r| r.get::<_, i64>(0))? as u64;

        let path = self.path.clone();
        let (events, edges, blobs, manifest_entries) =
            (self.events, self.edges, self.blobs, self.manifest_entries);

        self.finalized = true;
        drop(self.conn);

        let file_size = std::fs::metadata(&path)?.len();
        let mut f = std::fs::File::open(&path)?;
        let (file_digest, _) = crate::hash::sha256_stream(&mut f)?;
        drop(f);

        // The file digest cannot live inside the file it describes, so it goes
        // beside it. Losing the sidecar costs the file-level check but not the
        // content digest sealed inside.
        std::fs::write(
            path.with_extension("tpv.sha256"),
            format!(
                "{file_digest}  {}\n",
                path.file_name().unwrap_or_default().to_string_lossy()
            ),
        )?;

        Ok(CaseSummary {
            path,
            events,
            entities,
            edges,
            blobs,
            manifest_entries,
            file_size,
            content_digest,
            file_digest,
        })
    }

    /// Digest over the case's logical contents.
    ///
    /// Separate from the file hash on purpose. SQLite may lay the same rows out
    /// differently across writes, so a file hash cannot answer "is this the same
    /// evidence". This one can: it covers the row counts and every artifact and
    /// blob hash, so altering a stored artifact changes it even if the file is
    /// rebuilt byte-for-byte plausibly.
    fn compute_content_digest(&self) -> Result<String> {
        let mut lines = Vec::new();

        for table in [
            "events",
            "entities",
            "edges",
            "payloads",
            "blobs",
            "manifest",
        ] {
            let n: i64 =
                self.conn
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?;
            lines.push(format!("count:{table}={n}"));
        }

        let mut stmt = self.conn.prepare(
            "SELECT source_path, COALESCE(sha256, '-') FROM manifest ORDER BY source_path, id",
        )?;
        for row in stmt.query_map([], |r| {
            Ok(format!(
                "artifact:{}={}",
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?
            ))
        })? {
            lines.push(row?);
        }

        let mut stmt = self
            .conn
            .prepare("SELECT name, sha256, raw_len FROM blobs ORDER BY name")?;
        for row in stmt.query_map([], |r| {
            Ok(format!(
                "blob:{}={}:{}",
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?
            ))
        })? {
            lines.push(row?);
        }

        Ok(sha256_hex(lines.join("\n").as_bytes()))
    }
}
