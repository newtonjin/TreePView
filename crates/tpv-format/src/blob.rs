//! Chunked, seekable blob storage.
//!
//! A minidump of `lsass.exe` runs to tens of megabytes and a physical memory
//! image to several gigabytes. Storing either as one compressed unit would force
//! the viewer to inflate the whole thing to read a single page, so blobs are
//! split into fixed-size chunks that are each compressed on their own. Chunk
//! *n* of a blob is then reachable in one indexed lookup, and only that chunk is
//! decompressed.
//!
//! The chunking is on the *uncompressed* stream, which is what makes the
//! arithmetic from a byte offset to a chunk index a division rather than a scan
//! through a table of compressed extents.

use std::io::{self, Read, Seek, SeekFrom};

use rusqlite::Connection;

use crate::error::{FormatError, Result};

/// Metadata for one stored blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobInfo {
    pub id: i64,
    /// Case-unique logical name, for example `minidump/4242-notepad.exe`.
    pub name: String,
    /// Coarse type, so the viewer knows how to offer the content.
    pub kind: String,
    /// Length of the original, uncompressed stream.
    pub raw_len: u64,
    /// SHA-256 of the original stream, lowercase hex.
    pub sha256: String,
    pub chunk_size: u64,
    pub chunk_count: u64,
}

impl BlobInfo {
    /// Total compressed size actually occupied in the case file.
    pub fn stored_len(&self, conn: &Connection) -> Result<u64> {
        let n: i64 = conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(z)), 0) FROM blob_chunks WHERE blob_id = ?1",
            [self.id],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }
}

/// A `Read + Seek` view over a stored blob.
///
/// Holds exactly one decompressed chunk at a time. Sequential reads therefore
/// decompress each chunk once, and a seek within the current chunk costs
/// nothing, which is the access pattern a memory viewer actually produces.
pub struct BlobReader<'a> {
    conn: &'a Connection,
    info: BlobInfo,
    pos: u64,
    cached_index: Option<u64>,
    cached: Vec<u8>,
}

impl<'a> BlobReader<'a> {
    pub fn new(conn: &'a Connection, info: BlobInfo) -> Self {
        Self {
            conn,
            info,
            pos: 0,
            cached_index: None,
            cached: Vec::new(),
        }
    }

    pub fn info(&self) -> &BlobInfo {
        &self.info
    }

    pub fn len(&self) -> u64 {
        self.info.raw_len
    }

    pub fn is_empty(&self) -> bool {
        self.info.raw_len == 0
    }

    fn load_chunk(&mut self, index: u64) -> Result<()> {
        if self.cached_index == Some(index) {
            return Ok(());
        }
        let z: Vec<u8> = self
            .conn
            .query_row(
                "SELECT z FROM blob_chunks WHERE blob_id = ?1 AND idx = ?2",
                rusqlite::params![self.info.id, index as i64],
                |r| r.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => FormatError::BlobChunkMissing {
                    blob_id: self.info.id,
                    index,
                },
                other => FormatError::Sqlite(other),
            })?;

        self.cached = zstd::decode_all(&z[..])?;
        self.cached_index = Some(index);
        Ok(())
    }

    /// Read the whole blob and verify it against the recorded hash.
    ///
    /// Verification is a separate call rather than something [`Read`] does
    /// implicitly, because a partial read is a legitimate operation and only the
    /// caller knows whether it needs the integrity guarantee.
    pub fn read_all_verified(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.info.raw_len as usize);
        self.seek(SeekFrom::Start(0))?;
        self.read_to_end(&mut out)?;

        let actual = crate::hash::sha256_hex(&out);
        if actual != self.info.sha256 {
            return Err(FormatError::BlobIntegrity {
                name: self.info.name.clone(),
                expected: self.info.sha256.clone(),
                actual,
            });
        }
        Ok(out)
    }
}

impl Read for BlobReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.info.raw_len || buf.is_empty() {
            return Ok(0);
        }

        let index = self.pos / self.info.chunk_size;
        let offset_in_chunk = (self.pos % self.info.chunk_size) as usize;

        self.load_chunk(index)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let available = self.cached.len().saturating_sub(offset_in_chunk);
        if available == 0 {
            return Ok(0);
        }
        let n = available.min(buf.len());
        buf[..n].copy_from_slice(&self.cached[offset_in_chunk..offset_in_chunk + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for BlobReader<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let target = match from {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(n) => self.info.raw_len as i128 + n as i128,
            SeekFrom::Current(n) => self.pos as i128 + n as i128,
        };
        if target < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start of blob",
            ));
        }
        // Seeking past the end is legal and yields zero-length reads, matching
        // the behaviour of a real file.
        self.pos = target as u64;
        Ok(self.pos)
    }
}
