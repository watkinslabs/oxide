//! exFAT timestamps: the same stored pair FAT uses, plus a UTC offset carried
//! per timestamp.
//!
//! The pair itself is `dostime`. What exFAT adds is one byte beside each
//! reading saying which local time THAT reading was taken in — so a volume
//! written in two places carries both offsets, and a mount does not have to
//! guess one for the whole medium. The byte is a count of quarter-hours in
//! two's complement over seven bits, with the top bit saying whether it means
//! anything at all.
//!
//! A timestamp whose byte says nothing falls back to the mount's own offset,
//! which is what `time_offset=` is for. Every timestamp this implementation
//! WRITES says UTC explicitly, because that is a true statement about a
//! reading taken from a clock that has no timezone.

use vfs::timespec::Timespec64;

use crate::uapi::{TZ_MODULUS, TZ_NEGATIVE_FROM, TZ_UNIT_MINUTES, TZ_VALID};

pub use dostime::{DosTime, SECS_PER_DAY, SECS_PER_MIN};

/// How a mount reads a timestamp whose own byte declines to say.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct TimeConfig {
    /// Minutes the medium's local time runs ahead of UTC.
    pub offset_minutes: i32,
}

impl TimeConfig {
    /// # C: O(1)
    pub fn with_offset(offset_minutes: i32) -> Self { Self { offset_minutes } }

    /// Seconds to ADD to a stored reading to reach UTC. # C: O(1)
    pub fn to_utc(&self) -> i64 { -i64::from(self.offset_minutes) * SECS_PER_MIN }
}

/// One stored timestamp: the pair, and the byte that says what it means.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Stamp {
    pub fields: DosTime,
    pub tz: u8,
}

/// Seconds to ADD to a reading stamped with `tz` to reach UTC.
///
/// The field is a signed count of quarter-hours: values up to `0x3F` are
/// positive offsets, and the rest are negative, counted down from `0x80`. A
/// byte without the valid bit says nothing and is not consulted.
/// # C: O(1)
pub fn tz_to_utc(tz: u8) -> Option<i64> {
    if tz & TZ_VALID == 0 { return None; }
    let field = tz & !TZ_VALID;
    let quarters = if field <= TZ_NEGATIVE_FROM - 1 { i64::from(field) }
                   else { -i64::from(TZ_MODULUS - field) };
    Some(-quarters * TZ_UNIT_MINUTES * SECS_PER_MIN)
}

/// A stored timestamp as an instant.
///
/// The timestamp's own byte wins over the mount's option: a volume that says
/// which offset a reading was taken in is stating a fact, where the mount
/// option is a guess for readings that do not.
/// # C: O(1)
pub fn to_unix(cfg: &TimeConfig, stamp: Stamp) -> Timespec64 {
    let to_utc = tz_to_utc(stamp.tz).unwrap_or_else(|| cfg.to_utc());
    let (sec, nsec) = dostime::to_unix(stamp.fields, to_utc);
    Timespec64::new(sec, nsec)
}

/// Resolve the mount's fallback timezone exactly once for an inode read.
/// Linux's `sys_tz.tz_minuteswest` is minutes WEST of UTC, while exFAT's
/// `time_offset` is minutes AHEAD of UTC. # C: O(1)
pub fn effective_config(cfg: TimeConfig, sys_tz: bool) -> TimeConfig {
    if sys_tz {
        TimeConfig::with_offset(-vfs::inode_times::timezone_minuteswest())
    } else {
        cfg
    }
}

/// An instant as a stored timestamp.
///
/// The offset byte says UTC — offset zero, valid — because the reading came
/// from a clock with no timezone, and claiming an offset the reading was not
/// taken in would move every instant on the volume by that much.
/// # C: O(1)
pub fn from_unix(ts: Timespec64) -> Stamp {
    Stamp { fields: dostime::from_unix(ts.sec, ts.nsec, 0), tz: TZ_VALID }
}

/// An access time as the format stores it: two-second granularity and no
/// centisecond byte, so the sub-second part is dropped rather than rounded.
/// # C: O(1)
pub fn truncate_atime(ts: Timespec64) -> Timespec64 { Timespec64::from_secs(ts.sec & !1) }

/// A modification time as an access time's field pair can store it: the
/// centisecond byte is not written for the access timestamp, so the odd
/// second it would have carried is dropped.
/// # C: O(1)
pub fn without_centiseconds(stamp: Stamp) -> Stamp {
    Stamp { fields: DosTime { cs: 0, ..stamp.fields }, tz: stamp.tz }
}

#[cfg(test)]
#[path = "tests/time.rs"]
mod tests;
