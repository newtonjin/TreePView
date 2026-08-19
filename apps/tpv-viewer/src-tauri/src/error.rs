use std::path::PathBuf;

use serde::{Serialize, Serializer};

#[derive(Debug, thiserror::Error)]
pub enum ViewerError {
    #[error("{0}")]
    Case(#[from] tpv_format::FormatError),

    #[error("{0}")]
    Collect(#[from] tpv_collect::CollectError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("no case is open")]
    NoCaseOpen,

    #[error("event {0} is not in this case")]
    NoSuchEvent(i64),

    #[error("entity {0} is not in this case")]
    NoSuchEntity(String),

    #[error("{path} cannot be opened: {reason}")]
    UnsupportedFile { path: PathBuf, reason: String },
}

impl ViewerError {
    /// True when writing a derived case next to the image is what failed, so
    /// the viewer should fall back to the temp directory rather than give up.
    pub fn is_unwritable(&self) -> bool {
        fn denied(e: &std::io::Error) -> bool {
            matches!(
                e.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
            )
        }
        match self {
            ViewerError::Io(e) => denied(e),
            ViewerError::Collect(tpv_collect::CollectError::Io(e)) => denied(e),
            ViewerError::Collect(tpv_collect::CollectError::Format(tpv_format::FormatError::Io(e))) => {
                denied(e)
            }
            ViewerError::Case(tpv_format::FormatError::Io(e)) => denied(e),
            _ => false,
        }
    }
}

/// The frontend only ever displays these, so they cross the IPC boundary as the
/// message rather than as a tagged structure it would have to interpret.
impl Serialize for ViewerError {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ViewerError>;
