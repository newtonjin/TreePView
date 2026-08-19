//! The things a timeline event can be about.
//!
//! Entities are deduplicated by a natural key rather than by a generated id, so
//! the same executable seen in prefetch, in `$MFT` and in a live process list
//! collapses into one node the analyst can pivot on.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Host,
    /// A specific execution, not a PID. See [`ProcessKey`].
    Process,
    File,
    Module,
    User,
    NetEndpoint,
    RegistryKey,
    Service,
    ScheduledTask,
    Driver,
    /// A committed memory region, which is what injection findings hang off.
    MemoryRegion,
    Volume,
}

impl EntityKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            EntityKind::Host => "host",
            EntityKind::Process => "process",
            EntityKind::File => "file",
            EntityKind::Module => "module",
            EntityKind::User => "user",
            EntityKind::NetEndpoint => "net_endpoint",
            EntityKind::RegistryKey => "registry_key",
            EntityKind::Service => "service",
            EntityKind::ScheduledTask => "scheduled_task",
            EntityKind::Driver => "driver",
            EntityKind::MemoryRegion => "memory_region",
            EntityKind::Volume => "volume",
        }
    }

    pub fn from_str_lossy(s: &str) -> Option<Self> {
        Some(match s {
            "host" => EntityKind::Host,
            "process" => EntityKind::Process,
            "file" => EntityKind::File,
            "module" => EntityKind::Module,
            "user" => EntityKind::User,
            "net_endpoint" => EntityKind::NetEndpoint,
            "registry_key" => EntityKind::RegistryKey,
            "service" => EntityKind::Service,
            "scheduled_task" => EntityKind::ScheduledTask,
            "driver" => EntityKind::Driver,
            "memory_region" => EntityKind::MemoryRegion,
            "volume" => EntityKind::Volume,
            _ => return None,
        })
    }
}

/// Identity of one process *execution*.
///
/// A PID alone is not an identity: Windows recycles PIDs aggressively, and a
/// long collection can easily see two unrelated processes wearing the same
/// number. Pairing the PID with its creation time is what makes a process tree
/// trustworthy, and it is the difference between correctly attributing a network
/// connection and blaming an innocent process that inherited the PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProcessKey {
    pub pid: u32,
    /// Creation time in UTC nanoseconds. Zero when genuinely unknown, which
    /// downgrades the key to PID-only matching.
    pub start_ns: i64,
}

impl ProcessKey {
    pub const fn new(pid: u32, start_ns: i64) -> Self {
        Self { pid, start_ns }
    }

    /// A process whose creation time could not be determined. Correlation
    /// against these is best-effort and must be marked as such.
    pub const fn pid_only(pid: u32) -> Self {
        Self { pid, start_ns: 0 }
    }

    pub const fn is_pid_only(&self) -> bool {
        self.start_ns == 0
    }

    /// Stable natural key, used for entity deduplication across sources.
    pub fn natural_key(&self) -> String {
        if self.is_pid_only() {
            format!("proc:{}:unknown", self.pid)
        } else {
            format!("proc:{}:{}", self.pid, self.start_ns)
        }
    }
}

/// A node in the case graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entity {
    pub kind: EntityKind,
    /// Deduplication key, unique per case. For processes this is
    /// [`ProcessKey::natural_key`]; for files, the normalized full path.
    pub key: String,
    /// What the analyst sees in the tree.
    pub label: String,
    /// Kind-specific detail, kept open so a new artifact source does not force a
    /// schema migration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attrs: Option<serde_json::Value>,
}

impl Entity {
    pub fn new(kind: EntityKind, key: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            kind,
            key: key.into(),
            label: label.into(),
            attrs: None,
        }
    }

    pub fn with_attrs(mut self, attrs: serde_json::Value) -> Self {
        self.attrs = Some(attrs);
        self
    }

    pub fn process(key: ProcessKey, image: &str) -> Self {
        Self::new(EntityKind::Process, key.natural_key(), image)
    }

    pub fn file(path: &str) -> Self {
        let label = path
            .rsplit(['\\', '/'])
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or(path);
        Self::new(EntityKind::File, normalize_path(path), label)
    }
}

/// Normalize a filesystem path for use as a deduplication key.
///
/// Windows paths are case-insensitive and reach the same file through several
/// spellings, so prefetch (`\VOLUME{...}\WINDOWS\...`), `$MFT` (volume-relative)
/// and a live process image path must be folded together or the same binary
/// appears three times in the tree.
pub fn normalize_path(path: &str) -> String {
    let p = path.trim().replace('/', "\\");
    let p = p.strip_prefix("\\??\\").unwrap_or(&p);
    let p = p.strip_prefix("\\\\?\\").unwrap_or(p);
    p.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_key_distinguishes_recycled_pids() {
        let first = ProcessKey::new(4242, 1_000);
        let recycled = ProcessKey::new(4242, 9_000);
        assert_ne!(first.natural_key(), recycled.natural_key());
    }

    #[test]
    fn pid_only_keys_are_marked() {
        let k = ProcessKey::pid_only(1234);
        assert!(k.is_pid_only());
        assert_eq!(k.natural_key(), "proc:1234:unknown");
    }

    #[test]
    fn path_normalization_folds_spellings() {
        let expected = "c:\\windows\\system32\\cmd.exe";
        assert_eq!(normalize_path(r"C:\Windows\System32\cmd.exe"), expected);
        assert_eq!(normalize_path(r"\??\C:\Windows\System32\cmd.exe"), expected);
        assert_eq!(normalize_path(r"\\?\C:\Windows\System32\cmd.exe"), expected);
        assert_eq!(normalize_path("C:/Windows/System32/cmd.exe"), expected);
    }

    #[test]
    fn file_entity_label_is_the_basename() {
        let e = Entity::file(r"C:\Windows\System32\cmd.exe");
        assert_eq!(e.label, "cmd.exe");
        assert_eq!(e.key, "c:\\windows\\system32\\cmd.exe");
    }
}
