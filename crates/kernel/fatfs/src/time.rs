//! FAT timestamps: three fields of three different granularities, none of
//! them UTC.
//!
//! The stored pair itself — the two 16-bit words, the centisecond byte, the
//! 1980 epoch and the clamp at both ends — is `dostime`, shared with exFAT,
//! which stores the same pair. What FAT adds is the one thing that is its own:
//! a MOUNT-WIDE offset, from `tz=` or `time_offset=`, saying which local time
//! the whole medium was written in. exFAT instead carries an offset byte per
//! timestamp, which is why the offset is a parameter there and a mount option
//! here.

use vfs::timespec::Timespec64;

pub use dostime::{CivilTime, DosTime as FatTime, CS_MAX, SECS_PER_DAY};

#[cfg(test)]
#[path = "time/tests.rs"]
mod tests;

/// Seconds in a minute, for the offset the mount names.
const SECS_PER_MIN: i64 = 60;

/// The one time-related mount option: how far the medium's local time is
/// ahead of UTC, in minutes.
///
/// `set` distinguishes a mount that named an offset of zero from one that
/// named none — they behave the same here only because this kernel has no
/// system-wide timezone for the second case to fall back on.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct TimeConfig {
    pub set: bool,
    pub offset_minutes: i32,
}

impl TimeConfig {
    /// A mount that named an offset. # C: O(1)
    pub fn with_offset(offset_minutes: i32) -> Self { Self { set: true, offset_minutes } }

    /// Seconds to ADD to a stored reading to reach UTC. # C: O(1)
    fn to_utc(&self) -> i64 { -i64::from(self.offset_minutes) * SECS_PER_MIN }
}

/// A stored reading as a wall-clock instant. # C: O(1)
pub fn to_unix(cfg: &TimeConfig, fields: FatTime) -> Timespec64 {
    let (sec, nsec) = dostime::to_unix(fields, cfg.to_utc());
    Timespec64::new(sec, nsec)
}

/// A wall-clock instant as the fields that store it. # C: O(1)
pub fn from_unix(cfg: &TimeConfig, ts: Timespec64) -> FatTime {
    dostime::from_unix(ts.sec, ts.nsec, cfg.to_utc())
}

/// A modification time as the format can store it: two-second granularity,
/// no sub-second part.
///
/// Applied to the in-memory time as well as the stored one, so a program that
/// writes a file and stats it sees the time the medium will report after a
/// remount rather than one that changes under it.
/// # C: O(1)
pub fn truncate_mtime(ts: Timespec64) -> Timespec64 {
    Timespec64::from_secs(ts.sec & !1)
}

/// An access time as the format can store it: the local day it falls in.
///
/// The date field is all there is — no time of day — so the reading is taken
/// back to the previous LOCAL midnight, which is a different instant from the
/// previous UTC midnight whenever the mount names an offset.
/// # C: O(1)
pub fn truncate_atime(cfg: &TimeConfig, ts: Timespec64) -> Timespec64 {
    let local = ts.sec - cfg.to_utc();
    let remainder = local % SECS_PER_DAY;
    Timespec64::from_secs(local + cfg.to_utc() - remainder)
}
