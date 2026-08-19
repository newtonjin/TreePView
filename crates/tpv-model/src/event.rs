//! The unified timeline record.
//!
//! Every artifact, however it was parsed, lands in this one shape. That is what
//! lets a prefetch execution, a `4688` process-creation log and a live process
//! snapshot sit on the same axis and be filtered by the same query.

use serde::{Deserialize, Serialize};

use crate::time::Timestamp;

/// Where a fact came from. Provenance is not decoration: an analyst weighs a
/// `$MFT` timestamp differently from a prefetch one, and a finding that cannot
/// name its source is not defensible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Volatile state read from the running system.
    Live,
    /// Process memory: regions, or the contents of a minidump.
    Memory,
    Evtx,
    Prefetch,
    Mft,
    UsnJrnl,
    Registry,
    Amcache,
    Srum,
    ShimCache,
    Services,
    ScheduledTasks,
    /// The collector describing its own actions, for the custody trail.
    Collector,
    /// Linux sources, wired up in M7.
    Procfs,
    Journald,
    Auditd,
}

impl Source {
    pub const fn as_str(self) -> &'static str {
        match self {
            Source::Live => "live",
            Source::Memory => "memory",
            Source::Evtx => "evtx",
            Source::Prefetch => "prefetch",
            Source::Mft => "mft",
            Source::UsnJrnl => "usnjrnl",
            Source::Registry => "registry",
            Source::Amcache => "amcache",
            Source::Srum => "srum",
            Source::ShimCache => "shimcache",
            Source::Services => "services",
            Source::ScheduledTasks => "scheduled_tasks",
            Source::Collector => "collector",
            Source::Procfs => "procfs",
            Source::Journald => "journald",
            Source::Auditd => "auditd",
        }
    }

    pub fn from_str_lossy(s: &str) -> Option<Self> {
        Some(match s {
            "live" => Source::Live,
            "memory" => Source::Memory,
            "evtx" => Source::Evtx,
            "prefetch" => Source::Prefetch,
            "mft" => Source::Mft,
            "usnjrnl" => Source::UsnJrnl,
            "registry" => Source::Registry,
            "amcache" => Source::Amcache,
            "srum" => Source::Srum,
            "shimcache" => Source::ShimCache,
            "services" => Source::Services,
            "scheduled_tasks" => Source::ScheduledTasks,
            "collector" => Source::Collector,
            "procfs" => Source::Procfs,
            "journald" => Source::Journald,
            "auditd" => Source::Auditd,
            _ => return None,
        })
    }
}

/// What happened. Deliberately coarse: the fine detail lives in the payload, and
/// this field exists so the viewer can lane, colour and filter without decoding
/// every payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A process observed alive at collection time. Not a start event: the
    /// timestamp is the process creation time, but the observation is a snapshot.
    ProcessSnapshot,
    ProcessStart,
    ProcessEnd,
    ModuleLoad,
    ThreadStart,
    /// A committed memory region worth recording (private, executable, or
    /// otherwise anomalous).
    MemoryRegion,
    NetConnection,
    NetListen,
    FileCreate,
    FileWrite,
    FileDelete,
    FileRename,
    FileAccess,
    /// A `$MFT` record's timestamp set, carrying both `$SI` and `$FN`.
    FileMetadata,
    RegistryWrite,
    RegistryKeyLastWrite,
    /// Prefetch, Amcache, ShimCache: evidence a binary ran, without a live process.
    ExecutionEvidence,
    /// A configured autostart entry. Configuration observed at collection time
    /// rather than an event that happened then, which is why events of this kind
    /// carry an inferred timestamp.
    AutostartEntry,
    ServiceInstall,
    ServiceState,
    TaskRegister,
    DriverLoad,
    LogonSession,
    /// An event-log record that does not map to a more specific kind.
    LogRecord,
    /// The collector's own actions.
    CollectorAction,
}

impl EventKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            EventKind::ProcessSnapshot => "process_snapshot",
            EventKind::ProcessStart => "process_start",
            EventKind::ProcessEnd => "process_end",
            EventKind::ModuleLoad => "module_load",
            EventKind::ThreadStart => "thread_start",
            EventKind::MemoryRegion => "memory_region",
            EventKind::NetConnection => "net_connection",
            EventKind::NetListen => "net_listen",
            EventKind::FileCreate => "file_create",
            EventKind::FileWrite => "file_write",
            EventKind::FileDelete => "file_delete",
            EventKind::FileRename => "file_rename",
            EventKind::FileAccess => "file_access",
            EventKind::FileMetadata => "file_metadata",
            EventKind::RegistryWrite => "registry_write",
            EventKind::RegistryKeyLastWrite => "registry_key_lastwrite",
            EventKind::ExecutionEvidence => "execution_evidence",
            EventKind::AutostartEntry => "autostart_entry",
            EventKind::ServiceInstall => "service_install",
            EventKind::ServiceState => "service_state",
            EventKind::TaskRegister => "task_register",
            EventKind::DriverLoad => "driver_load",
            EventKind::LogonSession => "logon_session",
            EventKind::LogRecord => "log_record",
            EventKind::CollectorAction => "collector_action",
        }
    }

    pub fn from_str_lossy(s: &str) -> Option<Self> {
        Some(match s {
            "process_snapshot" => EventKind::ProcessSnapshot,
            "process_start" => EventKind::ProcessStart,
            "process_end" => EventKind::ProcessEnd,
            "module_load" => EventKind::ModuleLoad,
            "thread_start" => EventKind::ThreadStart,
            "memory_region" => EventKind::MemoryRegion,
            "net_connection" => EventKind::NetConnection,
            "net_listen" => EventKind::NetListen,
            "file_create" => EventKind::FileCreate,
            "file_write" => EventKind::FileWrite,
            "file_delete" => EventKind::FileDelete,
            "file_rename" => EventKind::FileRename,
            "file_access" => EventKind::FileAccess,
            "file_metadata" => EventKind::FileMetadata,
            "registry_write" => EventKind::RegistryWrite,
            "registry_key_lastwrite" => EventKind::RegistryKeyLastWrite,
            "execution_evidence" => EventKind::ExecutionEvidence,
            "autostart_entry" => EventKind::AutostartEntry,
            "service_install" => EventKind::ServiceInstall,
            "service_state" => EventKind::ServiceState,
            "task_register" => EventKind::TaskRegister,
            "driver_load" => EventKind::DriverLoad,
            "logon_session" => EventKind::LogonSession,
            "log_record" => EventKind::LogRecord,
            "collector_action" => EventKind::CollectorAction,
            _ => return None,
        })
    }

    /// Whether this kind belongs on a process lane in the viewer.
    pub const fn is_process_scoped(self) -> bool {
        matches!(
            self,
            EventKind::ProcessSnapshot
                | EventKind::ProcessStart
                | EventKind::ProcessEnd
                | EventKind::ModuleLoad
                | EventKind::ThreadStart
                | EventKind::MemoryRegion
                | EventKind::NetConnection
                | EventKind::NetListen
        )
    }
}

/// One row on the unified timeline.
///
/// The denormalized columns (`pid`, `image`, `user`, `path`, `remote`) are not
/// redundancy for its own sake: they are what the viewer filters and groups on,
/// and keeping them out of the JSON payload is what allows a filter over
/// millions of events to stay an indexed query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub ts: Timestamp,
    /// Set only for events with real duration, such as a logon session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts_end: Option<Timestamp>,
    pub source: Source,
    pub kind: EventKind,
    /// Natural key of the primary entity, resolved to a row id by the writer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// `addr:port` of the far end, for network events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    /// Windows Event ID / Sysmon ID / other log identifier. Denormalized so
    /// `id:4688` is an indexed filter instead of a payload scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_id: Option<u32>,
    /// One-line description shown in the timeline before the payload is opened.
    pub summary: String,
    /// Full source detail, stored deduplicated and zstd-compressed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

impl Event {
    pub fn new(ts: Timestamp, source: Source, kind: EventKind, summary: impl Into<String>) -> Self {
        Self {
            ts,
            ts_end: None,
            source,
            kind,
            entity_key: None,
            pid: None,
            ppid: None,
            image: None,
            user: None,
            path: None,
            remote: None,
            log_id: None,
            summary: summary.into(),
            payload: None,
        }
    }

    pub fn with_entity(mut self, key: impl Into<String>) -> Self {
        self.entity_key = Some(key.into());
        self
    }

    pub fn with_process(mut self, pid: u32, ppid: Option<u32>, image: Option<String>) -> Self {
        self.pid = Some(pid);
        self.ppid = ppid;
        self.image = image;
        self
    }

    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn with_remote(mut self, remote: impl Into<String>) -> Self {
        self.remote = Some(remote.into());
        self
    }

    pub fn with_log_id(mut self, log_id: u32) -> Self {
        self.log_id = Some(log_id);
        self
    }

    pub fn with_payload(mut self, payload: serde_json::Value) -> Self {
        self.payload = Some(payload);
        self
    }
}

/// How two entities relate. Edges are what make the view a graph rather than a
/// flat log, and what lets the viewer walk from a suspicious network connection
/// back to the process, its image on disk and the execution evidence for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    ParentOf,
    LoadedModule,
    ConnectedTo,
    WroteFile,
    ExecutedImage,
    OwnedByUser,
    HostsService,
    MapsRegion,
    /// Links a finding to the evidence supporting it.
    Evidences,
}

impl EdgeKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            EdgeKind::ParentOf => "parent_of",
            EdgeKind::LoadedModule => "loaded_module",
            EdgeKind::ConnectedTo => "connected_to",
            EdgeKind::WroteFile => "wrote_file",
            EdgeKind::ExecutedImage => "executed_image",
            EdgeKind::OwnedByUser => "owned_by_user",
            EdgeKind::HostsService => "hosts_service",
            EdgeKind::MapsRegion => "maps_region",
            EdgeKind::Evidences => "evidences",
        }
    }

    pub fn from_str_lossy(s: &str) -> Option<Self> {
        Some(match s {
            "parent_of" => EdgeKind::ParentOf,
            "loaded_module" => EdgeKind::LoadedModule,
            "connected_to" => EdgeKind::ConnectedTo,
            "wrote_file" => EdgeKind::WroteFile,
            "executed_image" => EdgeKind::ExecutedImage,
            "owned_by_user" => EdgeKind::OwnedByUser,
            "hosts_service" => EdgeKind::HostsService,
            "maps_region" => EdgeKind::MapsRegion,
            "evidences" => EdgeKind::Evidences,
            _ => return None,
        })
    }
}

/// A relation between two entities, identified by their natural keys.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    pub from_key: String,
    pub to_key: String,
    pub kind: EdgeKind,
    pub source: Source,
}

impl Edge {
    pub fn new(
        from_key: impl Into<String>,
        to_key: impl Into<String>,
        kind: EdgeKind,
        source: Source,
    ) -> Self {
        Self {
            from_key: from_key.into(),
            to_key: to_key.into(),
            kind,
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_names_roundtrip() {
        for s in [
            Source::Live,
            Source::Evtx,
            Source::Prefetch,
            Source::Mft,
            Source::UsnJrnl,
            Source::Collector,
        ] {
            assert_eq!(Source::from_str_lossy(s.as_str()), Some(s));
        }
    }

    #[test]
    fn event_kind_names_roundtrip() {
        for k in [
            EventKind::ProcessSnapshot,
            EventKind::NetConnection,
            EventKind::MemoryRegion,
            EventKind::ExecutionEvidence,
            EventKind::FileMetadata,
        ] {
            assert_eq!(EventKind::from_str_lossy(k.as_str()), Some(k));
        }
    }

    #[test]
    fn unknown_names_are_rejected_not_guessed() {
        assert_eq!(Source::from_str_lossy("nope"), None);
        assert_eq!(EventKind::from_str_lossy("nope"), None);
        assert_eq!(EdgeKind::from_str_lossy("nope"), None);
    }

    #[test]
    fn network_events_are_process_scoped() {
        assert!(EventKind::NetConnection.is_process_scoped());
        assert!(!EventKind::FileMetadata.is_process_scoped());
    }
}
