//! Hashing helpers.
//!
//! SHA-256 throughout. Every acquired artifact and every stored blob carries
//! one, and the case as a whole carries a digest over its logical contents so
//! tampering with rows is detectable independently of the file-level hash.

use std::io::Read;

use sha2::{Digest, Sha256};

/// SHA-256 of a byte slice, lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Streaming SHA-256 over a reader, returning the digest and the byte count.
///
/// Reads through a fixed buffer so hashing a multi-gigabyte memory image does
/// not require holding it in memory, which the collector's RAM ceiling forbids.
pub fn sha256_stream<R: Read>(reader: &mut R) -> std::io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), total))
}

/// Incremental hasher, for hashing a stream while it is being written out.
pub struct RollingSha256 {
    inner: Sha256,
    len: u64,
}

impl RollingSha256 {
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
            len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
        self.len += data.len() as u64;
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn finish(self) -> String {
        hex::encode(self.inner.finalize())
    }
}

impl Default for RollingSha256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let data = vec![0x5Au8; 3 * 1024 * 1024 + 17];
        let (streamed, len) = sha256_stream(&mut &data[..]).unwrap();
        assert_eq!(len, data.len() as u64);
        assert_eq!(streamed, sha256_hex(&data));
    }

    #[test]
    fn rolling_matches_oneshot() {
        let mut r = RollingSha256::new();
        r.update(b"ab");
        r.update(b"c");
        assert_eq!(r.len(), 3);
        assert_eq!(r.finish(), sha256_hex(b"abc"));
    }
}
