//! The OS-neutral model every TreePView component agrees on.
//!
//! The collector produces these types, the `.tpv` container stores them, the
//! viewer renders them and the findings layer reasons over them. Keeping the
//! model free of any Windows-specific shape is what stops the Windows-first
//! roadmap from producing a Windows-only architecture.
//!
//! The organising idea is that every artifact, no matter how it was parsed,
//! becomes an [`Event`] on one timeline, optionally about an [`Entity`], with a
//! [`Source`] that says where it came from and a [`Timestamp`] that never claims
//! more precision than the artifact had.

#![forbid(unsafe_code)]

pub mod custody;
pub mod entity;
pub mod event;
pub mod finding;
pub mod forest;
pub mod host;
pub mod time;

pub use custody::{AccessMethod, Custody, ManifestEntry};
pub use entity::{normalize_path, Entity, EntityKind, ProcessKey};
pub use event::{Edge, EdgeKind, Event, EventKind, Source};
pub use finding::{Confidence, Finding, Severity};
pub use forest::{
    entity_key_for, reconcile, EdgeState, FieldConfidence, FieldSource, Forest, ForestStats,
    Observation, ObservationRole, ParentClaim, ProcessField, ProcessInstance, SourceLayer,
    DEFAULT_MATCH_TOLERANCE_NS,
};
pub use host::{CollectionProfile, HostInfo, MemoryMode, ReferenceClock};
pub use time::{filetime_to_unix_ns, Timestamp, TsFlags, TsPrecision, TzSource};

/// Format version of the `.tpv` container this model corresponds to.
///
/// The reader refuses a case written by a newer major version rather than
/// silently misreading it.
pub const FORMAT_VERSION: u32 = 1;

/// Identifier for one collection run.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CaseId(pub String);

impl CaseId {
    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

impl std::fmt::Display for CaseId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_ids_are_unique() {
        assert_ne!(CaseId::generate(), CaseId::generate());
    }
}
