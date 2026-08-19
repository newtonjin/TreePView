//! Time normalization.
//!
//! Every artifact source carries a different clock: EVTX is UTC, prefetch and
//! `$STANDARD_INFORMATION` are `FILETIME`, registry last-write is `FILETIME`,
//! SRUM is local time. Correlation is only meaningful once they share one scale,
//! so everything converges on UTC nanoseconds here.
//!
//! Two properties matter more than convenience:
//!
//! 1. **Precision is never inflated.** A `FILETIME` has 100 ns granularity and a
//!    FAT-era timestamp has 2 s; storing both as nanoseconds would imply an
//!    accuracy neither has. [`TsPrecision`] travels with every timestamp so the
//!    viewer can render a bar instead of a point.
//! 2. **Out-of-range is evidence, not an error.** i64 nanoseconds spans roughly
//!    1678-2262. A `FILETIME` of 0 (1601) or a timestomp to the year 3000 falls
//!    outside that, so the value is clamped for sorting and
//!    [`TsFlags::OUT_OF_RANGE`] is raised. The anomaly stays visible instead of
//!    being silently coerced into a plausible-looking date.

use serde::{Deserialize, Serialize};

/// Nanoseconds between the `FILETIME` epoch (1601-01-01) and the Unix epoch.
const FILETIME_EPOCH_OFFSET_NS: i128 = 11_644_473_600_000_000_000;

/// A `FILETIME` tick is 100 ns.
const FILETIME_TICK_NS: i128 = 100;

/// How much of the stored timestamp is actually meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TsPrecision {
    Nanosecond,
    /// `FILETIME` native granularity.
    HundredNanos,
    Microsecond,
    Millisecond,
    Second,
    /// FAT / some prefetch-adjacent artifacts.
    TwoSeconds,
    Minute,
    Hour,
    Day,
    /// The source gave a time but not a trustworthy resolution.
    Unknown,
}

impl TsPrecision {
    /// Width of the uncertainty window in nanoseconds, for rendering a
    /// timestamp as an interval rather than an instant.
    pub const fn window_ns(self) -> i64 {
        match self {
            TsPrecision::Nanosecond => 1,
            TsPrecision::HundredNanos => 100,
            TsPrecision::Microsecond => 1_000,
            TsPrecision::Millisecond => 1_000_000,
            TsPrecision::Second => 1_000_000_000,
            TsPrecision::TwoSeconds => 2_000_000_000,
            TsPrecision::Minute => 60_000_000_000,
            TsPrecision::Hour => 3_600_000_000_000,
            TsPrecision::Day => 86_400_000_000_000,
            TsPrecision::Unknown => 0,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            TsPrecision::Nanosecond => "ns",
            TsPrecision::HundredNanos => "100ns",
            TsPrecision::Microsecond => "us",
            TsPrecision::Millisecond => "ms",
            TsPrecision::Second => "s",
            TsPrecision::TwoSeconds => "2s",
            TsPrecision::Minute => "min",
            TsPrecision::Hour => "h",
            TsPrecision::Day => "d",
            TsPrecision::Unknown => "unknown",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "ns" => TsPrecision::Nanosecond,
            "100ns" => TsPrecision::HundredNanos,
            "us" => TsPrecision::Microsecond,
            "ms" => TsPrecision::Millisecond,
            "s" => TsPrecision::Second,
            "2s" => TsPrecision::TwoSeconds,
            "min" => TsPrecision::Minute,
            "h" => TsPrecision::Hour,
            "d" => TsPrecision::Day,
            _ => TsPrecision::Unknown,
        }
    }
}

/// How the timestamp arrived at UTC, which decides how much to trust it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TzSource {
    /// The artifact stores UTC natively (EVTX, `FILETIME`).
    NativeUtc,
    /// Local time converted using the collected host time-zone bias. Only as
    /// correct as the host clock and bias were at collection time.
    ConvertedFromHostLocal,
    /// Local time with no reliable bias available; stored as if UTC.
    AssumedUtc,
}

impl TzSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            TzSource::NativeUtc => "native_utc",
            TzSource::ConvertedFromHostLocal => "converted_local",
            TzSource::AssumedUtc => "assumed_utc",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "native_utc" => TzSource::NativeUtc,
            "converted_local" => TzSource::ConvertedFromHostLocal,
            _ => TzSource::AssumedUtc,
        }
    }
}

/// Bit flags recording what happened to a timestamp on its way in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash, Serialize, Deserialize)]
pub struct TsFlags(pub u32);

impl TsFlags {
    pub const NONE: TsFlags = TsFlags(0);
    /// The source value fell outside the i64-nanosecond window and was clamped.
    /// The clamp itself is forensically interesting: a `FILETIME` of 0 means the
    /// field was never set, and a far-future value usually means tampering.
    pub const OUT_OF_RANGE: TsFlags = TsFlags(1 << 0);
    /// The source stored zero, i.e. "no timestamp" rather than "the epoch".
    pub const ZERO_SOURCE: TsFlags = TsFlags(1 << 1);
    /// Derived by inference (for example a process start reconstructed from a
    /// child's parent reference) rather than read from an artifact.
    pub const INFERRED: TsFlags = TsFlags(1 << 2);

    /// Flags that make a timestamp unusable as a *position* on the timeline.
    ///
    /// [`Self::INFERRED`] is deliberately excluded. An inferred timestamp is a
    /// real instant — the moment the collector looked — it simply is not the
    /// moment the thing happened. Treating it as unplaceable would drop every
    /// service, autorun, loaded module and open socket off the axis, which is
    /// most of what a live triage collects.
    pub const UNPLACEABLE: TsFlags = TsFlags(Self::OUT_OF_RANGE.0 | Self::ZERO_SOURCE.0);

    pub const fn contains(self, other: TsFlags) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn union(self, other: TsFlags) -> TsFlags {
        TsFlags(self.0 | other.0)
    }
}

/// A point on the unified timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timestamp {
    /// UTC nanoseconds since the Unix epoch. Clamped, so always a valid sort key.
    pub utc_ns: i64,
    pub precision: TsPrecision,
    pub tz_source: TzSource,
    pub flags: TsFlags,
}

impl Timestamp {
    pub const fn new(utc_ns: i64, precision: TsPrecision, tz_source: TzSource) -> Self {
        Self {
            utc_ns,
            precision,
            tz_source,
            flags: TsFlags::NONE,
        }
    }

    /// Convert a raw Windows `FILETIME` (100 ns ticks since 1601-01-01 UTC).
    ///
    /// A zero tick count means "unset" in every Windows artifact that uses this
    /// type, so it is flagged rather than rendered as 1601-01-01.
    pub fn from_filetime(ticks: i64) -> Self {
        let mut flags = TsFlags::NONE;
        if ticks == 0 {
            flags = flags.union(TsFlags::ZERO_SOURCE);
        }
        let as_ns = (ticks as i128) * FILETIME_TICK_NS - FILETIME_EPOCH_OFFSET_NS;
        let (utc_ns, clamped) = clamp_i128_ns(as_ns);
        if clamped {
            flags = flags.union(TsFlags::OUT_OF_RANGE);
        }
        Self {
            utc_ns,
            precision: TsPrecision::HundredNanos,
            tz_source: TzSource::NativeUtc,
            flags,
        }
    }

    /// Convert from a 128-bit nanosecond count, as produced by `jiff::Timestamp`.
    pub fn from_unix_nanos_i128(ns: i128, precision: TsPrecision) -> Self {
        let (utc_ns, clamped) = clamp_i128_ns(ns);
        Self {
            utc_ns,
            precision,
            tz_source: TzSource::NativeUtc,
            flags: if clamped {
                TsFlags::OUT_OF_RANGE
            } else {
                TsFlags::NONE
            },
        }
    }

    /// Convert a Unix-epoch second count (`/proc`, journald, ext4).
    pub fn from_unix_secs(secs: i64, precision: TsPrecision) -> Self {
        Self::from_unix_nanos_i128((secs as i128) * 1_000_000_000, precision)
    }

    /// Mark this timestamp as reconstructed rather than observed.
    pub fn inferred(mut self) -> Self {
        self.flags = self.flags.union(TsFlags::INFERRED);
        self
    }

    /// End of the uncertainty window implied by [`Self::precision`].
    pub fn window_end_ns(&self) -> i64 {
        self.utc_ns.saturating_add(self.precision.window_ns())
    }

    /// True when the value should not be read as a real wall-clock time.
    pub fn is_suspect(&self) -> bool {
        self.flags.contains(TsFlags::OUT_OF_RANGE) || self.flags.contains(TsFlags::ZERO_SOURCE)
    }

    /// Render as RFC 3339 UTC, showing exactly as many fractional digits as
    /// [`Self::precision`] justifies.
    ///
    /// This exists here, rather than in whatever is displaying the timestamp,
    /// for a specific reason: `utc_ns` is an i64 whose magnitude passed
    /// JavaScript's 2^53 exact-integer range in 2004, so any timestamp formatted
    /// in the viewer's frontend would be wrong by up to 256 ns. A report quoting
    /// that value would be quoting a number the evidence never contained.
    /// Formatting where the integer is still exact removes the problem instead
    /// of hiding it.
    pub fn to_rfc3339(&self) -> String {
        if self.flags.contains(TsFlags::ZERO_SOURCE) {
            return "(not set)".into();
        }
        if self.flags.contains(TsFlags::OUT_OF_RANGE) {
            return "(out of range)".into();
        }

        let (days, ns_of_day) = div_rem_euclid(self.utc_ns, 86_400_000_000_000);
        let (y, m, d) = civil_from_days(days);
        let (hh, rest) = (ns_of_day / 3_600_000_000_000, ns_of_day % 3_600_000_000_000);
        let (mm, rest) = (rest / 60_000_000_000, rest % 60_000_000_000);
        let (ss, sub) = (rest / 1_000_000_000, rest % 1_000_000_000);

        let base = format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}");
        match self.precision {
            TsPrecision::Nanosecond | TsPrecision::Unknown => {
                format!("{base}.{sub:09}Z")
            }
            TsPrecision::HundredNanos => format!("{base}.{:07}Z", sub / 100),
            TsPrecision::Microsecond => format!("{base}.{:06}Z", sub / 1_000),
            TsPrecision::Millisecond => format!("{base}.{:03}Z", sub / 1_000_000),
            _ => format!("{base}Z"),
        }
    }
}

/// Euclidean division, so times before 1970 floor towards the earlier day
/// instead of truncating towards zero and landing on the wrong date.
fn div_rem_euclid(a: i64, b: i64) -> (i64, i64) {
    (a.div_euclid(b), a.rem_euclid(b))
}

/// Days since 1970-01-01 to a proleptic Gregorian date.
///
/// Howard Hinnant's `civil_from_days`, which is exact over the whole i64 range
/// and needs no tables or dependencies. A date library would be a heavier
/// dependency than the collector should carry for a dozen lines of arithmetic.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Clamp a 128-bit nanosecond count into i64, reporting whether it was clamped.
fn clamp_i128_ns(ns: i128) -> (i64, bool) {
    const MIN: i128 = i64::MIN as i128;
    const MAX: i128 = i64::MAX as i128;
    if ns < MIN {
        (i64::MIN, true)
    } else if ns > MAX {
        (i64::MAX, true)
    } else {
        (ns as i64, false)
    }
}

/// Convert a `FILETIME` to UTC nanoseconds without the surrounding metadata.
pub fn filetime_to_unix_ns(ticks: i64) -> i64 {
    Timestamp::from_filetime(ticks).utc_ns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_epoch_maps_to_unix_epoch() {
        // 1970-01-01 expressed as FILETIME ticks.
        let ticks = (FILETIME_EPOCH_OFFSET_NS / FILETIME_TICK_NS) as i64;
        assert_eq!(Timestamp::from_filetime(ticks).utc_ns, 0);
    }

    #[test]
    fn known_filetime_converts_exactly() {
        // A real prefetch run time, 2020-09-19T03:40:49.4103203Z, cross-checked
        // against Windows' own FromFileTimeUtc. Checking an artifact value
        // rather than a round number is what catches an epoch offset that is
        // wrong by a constant.
        let ts = Timestamp::from_filetime(132_449_604_494_103_203);
        assert_eq!(ts.utc_ns, 1_600_486_849_410_320_300);
        assert_eq!(ts.precision, TsPrecision::HundredNanos);
        assert!(!ts.is_suspect());

        // The sub-second component must survive, since ordering events inside
        // one second is exactly what a timeline is for.
        assert_eq!(ts.utc_ns % 1_000_000_000, 410_320_300);
    }

    #[test]
    fn zero_filetime_is_flagged_not_dated() {
        let ts = Timestamp::from_filetime(0);
        assert!(ts.flags.contains(TsFlags::ZERO_SOURCE));
        // 1601 is far below the i64-nanosecond floor, so it also clamps.
        assert!(ts.flags.contains(TsFlags::OUT_OF_RANGE));
        assert!(ts.is_suspect());
    }

    #[test]
    fn far_future_timestomp_is_flagged() {
        let ts = Timestamp::from_filetime(i64::MAX);
        assert!(ts.flags.contains(TsFlags::OUT_OF_RANGE));
        assert_eq!(ts.utc_ns, i64::MAX);
    }

    #[test]
    fn formatting_shows_only_the_digits_the_source_had() {
        let ns = 1_600_486_849_410_320_300;
        let at = |p| Timestamp::new(ns, p, TzSource::NativeUtc).to_rfc3339();

        assert_eq!(at(TsPrecision::Nanosecond), "2020-09-19T03:40:49.410320300Z");
        assert_eq!(at(TsPrecision::HundredNanos), "2020-09-19T03:40:49.4103203Z");
        assert_eq!(at(TsPrecision::Microsecond), "2020-09-19T03:40:49.410320Z");
        assert_eq!(at(TsPrecision::Millisecond), "2020-09-19T03:40:49.410Z");
        // A two-second artifact must not display a sub-second component it
        // never recorded.
        assert_eq!(at(TsPrecision::TwoSeconds), "2020-09-19T03:40:49Z");
        assert_eq!(at(TsPrecision::Day), "2020-09-19T03:40:49Z");
    }

    #[test]
    fn formatting_handles_the_epoch_and_dates_before_it() {
        let f = |ns| Timestamp::new(ns, TsPrecision::Second, TzSource::NativeUtc).to_rfc3339();
        assert_eq!(f(0), "1970-01-01T00:00:00Z");
        assert_eq!(f(-1_000_000_000), "1969-12-31T23:59:59Z");
        // A leap day, which is where a hand-rolled calendar usually breaks.
        assert_eq!(f(1_582_934_400_000_000_000), "2020-02-29T00:00:00Z");
    }

    #[test]
    fn suspect_timestamps_refuse_to_render_as_dates() {
        // Showing 1601-01-01 for an unset FILETIME invites an analyst to treat
        // "no value" as "a value", which is the whole reason these are flagged.
        assert_eq!(Timestamp::from_filetime(0).to_rfc3339(), "(not set)");
        assert_eq!(
            Timestamp::from_filetime(i64::MAX).to_rfc3339(),
            "(out of range)"
        );
    }

    #[test]
    fn precision_windows_are_ordered() {
        assert!(TsPrecision::Nanosecond.window_ns() < TsPrecision::Second.window_ns());
        assert!(TsPrecision::Second.window_ns() < TsPrecision::Day.window_ns());
    }

    #[test]
    fn precision_roundtrips_through_text() {
        for p in [
            TsPrecision::Nanosecond,
            TsPrecision::HundredNanos,
            TsPrecision::Second,
            TsPrecision::TwoSeconds,
            TsPrecision::Day,
        ] {
            assert_eq!(TsPrecision::from_str_lossy(p.as_str()), p);
        }
    }
}
