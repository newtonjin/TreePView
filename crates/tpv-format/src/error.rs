use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{path} is not a TreePView case file (application_id {found:#x})")]
    NotACase { path: PathBuf, found: i32 },

    /// Refusing to guess at a layout we do not know is the point: a case written
    /// by a newer collector may store fields this reader would silently drop.
    #[error("case format version {found} is newer than supported version {supported}")]
    UnsupportedVersion { found: u32, supported: u32 },

    #[error("case is missing required metadata key `{0}`")]
    MissingMeta(&'static str),

    #[error("blob {0} not found")]
    BlobNotFound(i64),

    #[error("blob {blob_id} chunk {index} is missing; the case file is truncated or corrupt")]
    BlobChunkMissing { blob_id: i64, index: u64 },

    #[error(
        "blob {name} failed verification: expected sha256 {expected}, computed {actual}"
    )]
    BlobIntegrity {
        name: String,
        expected: String,
        actual: String,
    },

    #[error("case has already been finalized and is read-only")]
    AlreadyFinalized,

    #[error("refusing to overwrite existing case file {0}")]
    CaseExists(PathBuf),
}

pub type Result<T> = std::result::Result<T, FormatError>;
