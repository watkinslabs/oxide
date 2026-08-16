//! NTFS timestamps: a count of hundred-nanosecond units since 1601.
//!
//! Signed, and deliberately: a volume can carry an instant before the Unix
//! epoch, and reading the count as unsigned turns 1970 minus a second into a
//! date half a million years away.

use vfs::timespec::Timespec64;

use crate::uapi::{NT_EPOCH_DELTA_SECS, NT_NSEC_PER_UNIT, NT_UNITS_PER_SEC};

/// A stored count as an instant. # C: O(1)
pub fn to_unix(nt: i64) -> Timespec64 {
    let shifted = nt - NT_UNITS_PER_SEC * NT_EPOCH_DELTA_SECS;
    // Euclidean division, so an instant before the epoch floors to the second
    // before it rather than truncating towards zero and landing a second late.
    let sec = shifted.div_euclid(NT_UNITS_PER_SEC);
    let rem = shifted.rem_euclid(NT_UNITS_PER_SEC);
    Timespec64::new(sec, (rem as u32).saturating_mul(NT_NSEC_PER_UNIT))
}

/// An instant as a stored count. # C: O(1)
pub fn from_unix(ts: Timespec64) -> i64 {
    NT_UNITS_PER_SEC.saturating_mul(ts.sec + NT_EPOCH_DELTA_SECS)
        + i64::from(ts.nsec / NT_NSEC_PER_UNIT)
}

/// The granularity the format stores, applied to an in-memory instant.
///
/// A program that writes a file and stats it sees the time the medium will
/// report after a remount rather than one that changes under it.
/// # C: O(1)
pub fn truncate(ts: Timespec64) -> Timespec64 {
    Timespec64::new(ts.sec, (ts.nsec / NT_NSEC_PER_UNIT) * NT_NSEC_PER_UNIT)
}

#[cfg(test)]
#[path = "tests/time.rs"]
mod tests;
