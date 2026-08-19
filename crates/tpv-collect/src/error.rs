use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    #[error("case container: {0}")]
    Format(#[from] tpv_format::FormatError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("memory image: {0}")]
    Memory(#[from] tpv_memory::MemoryError),

    /// Refusing to write onto the volume being examined is a deliberate stop,
    /// not a failure: continuing would damage the evidence.
    #[error("refusing to write the case here: {reason}")]
    UnsafeOutput { path: PathBuf, reason: String },

    #[error("this collector only runs on Windows; the Linux collector arrives in M7")]
    UnsupportedPlatform,
}

pub type Result<T> = std::result::Result<T, CollectError>;
