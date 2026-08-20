//! The `.tpv` portable case container.
//!
//! A case is one SQLite file holding the normalized timeline, the entity graph,
//! zstd-compressed source payloads, chunked binaries, the chain of custody, and
//! a regenerable findings table. One file is the whole point: it is what gets
//! carried off the host under examination and opened on an analyst workstation
//! that never touched the incident.
//!
//! Two halves, deliberately asymmetric:
//!
//! - [`CaseWriter`] runs on the host under examination. Append-only, bounded
//!   memory, and survivable: a collection killed halfway still leaves a readable
//!   case containing everything gathered before the interruption.
//! - [`CaseReader`] runs on the analyst's machine. Read-only at the SQLite
//!   level, so a viewer is structurally incapable of modifying evidence, with
//!   the single exception of regenerating derived findings.

#![forbid(unsafe_code)]

pub mod blob;
pub mod error;
pub mod export;
pub mod findings;
pub mod forest;
pub mod hash;
pub mod reader;
pub mod schema;
pub mod writer;

pub use blob::{BlobInfo, BlobReader};
pub use error::{FormatError, Result};
pub use export::{case_markdown, events_csv, events_jsonl};
pub use reader::{
    CaseMeta, CaseReader, Counts, EntityRow, EventFilter, EventRow, LaneSeries, ProcessNode,
    RelatedEntity, RelatedLog, TimeBin,
};
pub use schema::{APPLICATION_ID, SCHEMA_VERSION};
pub use writer::{CaseInit, CaseSummary, CaseWriter};

#[cfg(test)]
mod tests;
