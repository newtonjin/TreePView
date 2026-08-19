//! Default case filename: `HOSTNAME-YYYYMMDDTHHMMSSZ.tpv`.

use std::path::{Path, PathBuf};

use tpv_model::Timestamp;

/// Build `HOSTNAME-YYYYMMDDTHHMMSSZ.tpv` from the live host clock.
pub fn default_filename(hostname: &str, at: Timestamp) -> String {
    format!("{}-{}.tpv", sanitize_hostname(hostname), compact_utc(at))
}

/// Resolve `--out`: omitted or an existing directory gets an automatic name;
/// any other path is used as the file.
pub fn resolve_out(out: Option<&Path>, hostname: &str, at: Timestamp) -> PathBuf {
    let name = default_filename(hostname, at);
    match out {
        None => std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(name),
        Some(p) if p.is_dir() => p.join(name),
        Some(p) => p.to_path_buf(),
    }
}

fn sanitize_hostname(hostname: &str) -> String {
    let cleaned: String = hostname
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' | ' ' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    let cleaned = cleaned.trim_matches('_');
    if cleaned.is_empty() {
        "host".into()
    } else {
        cleaned.to_string()
    }
}

fn compact_utc(at: Timestamp) -> String {
    let rfc = at.to_rfc3339();
    let digits: String = rfc.chars().filter(|c| c.is_ascii_digit()).take(14).collect();
    if digits.len() >= 14 {
        format!("{}T{}Z", &digits[..8], &digits[8..14])
    } else {
        "unknown".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpv_model::{TsPrecision, TzSource};

    #[test]
    fn filename_is_host_and_utc() {
        let ts = Timestamp::new(
            1_700_000_000_000_000_000,
            TsPrecision::Second,
            TzSource::NativeUtc,
        );
        let name = default_filename("GELADEIRA", ts);
        assert!(name.starts_with("GELADEIRA-"), "{name}");
        assert!(name.ends_with(".tpv"), "{name}");
        assert!(!name.contains(':'));
    }

    #[test]
    fn directory_out_gets_the_generated_name() {
        let dir = tempfile::tempdir().unwrap();
        let ts = Timestamp::new(1_700_000_000_000_000_000, TsPrecision::Second, TzSource::NativeUtc);
        let path = resolve_out(Some(dir.path()), "BOX", ts);
        assert_eq!(path.parent().unwrap(), dir.path());
        assert!(path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("BOX-"));
    }

    #[test]
    fn file_out_is_kept() {
        let ts = Timestamp::new(1_700_000_000_000_000_000, TsPrecision::Second, TzSource::NativeUtc);
        let path = resolve_out(Some(Path::new(r"E:\case.tpv")), "BOX", ts);
        assert_eq!(path, PathBuf::from(r"E:\case.tpv"));
    }
}
