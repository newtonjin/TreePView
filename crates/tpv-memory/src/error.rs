use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum MemoryError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("{path} is not a memory image this build recognises: {reason}")]
    UnknownFormat { path: PathBuf, reason: String },

    #[error("the image is truncated: {0}")]
    Truncated(String),

    /// Every acquisition tool produces gaps, so an unmapped read is an ordinary
    /// outcome rather than a failure, and callers are expected to handle it.
    #[error("physical address {0:#x} is not present in this image")]
    NotMapped(u64),

    #[error("virtual address {addr:#x} does not translate under DTB {dtb:#x}")]
    NotTranslated { addr: u64, dtb: u64 },

    #[error("no page-table root could be found; the image may be from a paused VM mid-boot, encrypted, or not x86-64")]
    NoDirectoryTableBase,

    #[error("could not locate the process list: {0}")]
    NoProcessList(String),
}

pub type Result<T> = std::result::Result<T, MemoryError>;
