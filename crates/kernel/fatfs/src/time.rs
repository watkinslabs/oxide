//! FAT timestamps: three fields of three different granularities, none of
//! them UTC.
//!
//! What the format stores is a LOCAL wall-clock reading, and it stores three
//! of them at three resolutions: modification to two seconds, creation to ten
//! milliseconds via an extra byte, access to a whole day. A mount's `tz=` or
//! `time_offset=` says which local time the medium was written in; without
//! one the readings are taken as UTC.
//!
//! The epoch is 1980 and the year field is seven bits, so the format cannot
//! represent anything before 1980-01-01 or after 2107-12-31. Both ends CLAMP
//! rather than wrap: a file dated 1970 written to a stick reads back as 1980,
//! which is wrong by a decade and still ordered, where a wrapped value would
//! read as a date in the future.

use vfs::timespec::Timespec64;

/// Module manifest:
/// - `civil`: the calendar arithmetic both directions need.
mod civil;

#[cfg(test)]
#[path = "time/tests.rs"]
mod tests;

pub use civil::CivilTime;

/// Seconds in the units the fields count in.
const SECS_PER_MIN: i64 = 60;
const SECS_PER_HOUR: i64 = 60 * 60;
pub const SECS_PER_DAY: i64 = SECS_PER_HOUR * 24;

/// Seconds between the Unix epoch and the FAT epoch: ten years holding two
/// leap days.
const EPOCH_DELTA_DAYS: i64 = 365 * 10 + 2;

/// First and last year the seven-bit field can name, counted from 1980.
const YEAR_MIN: i32 = 1980;
const YEAR_MAX: i32 = 2107;
/// 2100 is the one multiple of four in range that is not a leap year.
const YEAR_2100: i64 = 120;

/// The clamped low end: 1980-01-01 00:00:00, in the fields' own encoding.
const CLAMP_LOW_TIME: u16 = 0;
const CLAMP_LOW_DATE: u16 = (1 << DATE_MONTH_SHIFT) | 1;
/// The clamped high end: 2107-12-31 23:59:58, and the last centisecond it can
/// name.
const CLAMP_HIGH_TIME: u16 = (23 << TIME_HOUR_SHIFT) | (59 << TIME_MIN_SHIFT) | 29;
const CLAMP_HIGH_DATE: u16 = (127 << DATE_YEAR_SHIFT) | (12 << DATE_MONTH_SHIFT) | 31;
const CLAMP_HIGH_CS: u8 = 199;

/// Field positions within the two 16-bit words.
const TIME_SEC_MASK: u16 = 0x1f;
const TIME_MIN_SHIFT: u32 = 5;
const TIME_MIN_MASK: u16 = 0x3f;
const TIME_HOUR_SHIFT: u32 = 11;
const DATE_DAY_MASK: u16 = 0x1f;
const DATE_MONTH_SHIFT: u32 = 5;
const DATE_MONTH_MASK: u16 = 0xf;
const DATE_YEAR_SHIFT: u32 = 9;

/// The seconds field counts in twos.
const SEC_GRANULARITY: u32 = 1;
/// Centiseconds per second, and nanoseconds per centisecond.
const CS_PER_SEC: u8 = 100;
const NSEC_PER_CS: u32 = 10_000_000;
/// Largest value the centisecond byte carries: two whole seconds' worth.
pub const CS_MAX: u8 = 199;

/// Day number of the 1st of each month in a non-leap year, indexed by month.
///
/// Sixteen entries because the month field is four bits: a corrupt record can
/// name a month that does not exist, and the reference reads it rather than
/// rejecting the entry.
const DAYS_IN_YEAR: [i64; 16] = [0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 0, 0, 0];

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

/// The three fields one entry's timestamp occupies.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct FatTime {
    pub time: u16,
    pub date: u16,
    /// Centiseconds, only ever stored for the creation time.
    pub cs: u8,
}

/// A stored reading as a wall-clock instant.
///
/// Nothing here can fail: every bit pattern is a date, because the fields are
/// clamped up to a valid month and day rather than rejected. An entry another
/// system wrote with a zero date reads as the epoch the format starts at, not
/// as an error that would hide the whole directory.
/// # C: O(1)
pub fn to_unix(cfg: &TimeConfig, fields: FatTime) -> Timespec64 {
    let year = i64::from(fields.date >> DATE_YEAR_SHIFT);
    let month = i64::from((fields.date >> DATE_MONTH_SHIFT) & DATE_MONTH_MASK).max(1);
    let day = i64::from(fields.date & DATE_DAY_MASK).max(1) - 1;

    let mut leap = (year + 3) / 4;
    if year > YEAR_2100 { leap -= 1; }
    if is_leap(year) && month > 2 { leap += 1; }

    let mut second = i64::from(fields.time & TIME_SEC_MASK) << SEC_GRANULARITY;
    second += i64::from((fields.time >> TIME_MIN_SHIFT) & TIME_MIN_MASK) * SECS_PER_MIN;
    second += i64::from(fields.time >> TIME_HOUR_SHIFT) * SECS_PER_HOUR;
    second += (year * 365 + leap + DAYS_IN_YEAR[month as usize] + day + EPOCH_DELTA_DAYS)
        * SECS_PER_DAY;
    second += cfg.to_utc();

    if fields.cs != 0 {
        Timespec64::new(second + i64::from(fields.cs / CS_PER_SEC),
                        u32::from(fields.cs % CS_PER_SEC) * NSEC_PER_CS)
    } else {
        Timespec64::from_secs(second)
    }
}

/// A wall-clock instant as the fields that store it.
///
/// Out of range at either end clamps to the end it passed. The centisecond
/// byte carries the odd second the two-second field cannot, which is why the
/// creation time can name an odd second and the modification time cannot.
/// # C: O(1)
pub fn from_unix(cfg: &TimeConfig, ts: Timespec64) -> FatTime {
    let local = ts.sec - cfg.to_utc();
    let tm = civil::from_unix_seconds(local);

    if tm.year < YEAR_MIN {
        return FatTime { time: CLAMP_LOW_TIME, date: CLAMP_LOW_DATE, cs: 0 };
    }
    if tm.year > YEAR_MAX {
        return FatTime { time: CLAMP_HIGH_TIME, date: CLAMP_HIGH_DATE, cs: CLAMP_HIGH_CS };
    }

    let year = (tm.year - YEAR_MIN) as u16;
    let time = (u16::from(tm.hour) << TIME_HOUR_SHIFT)
        | (u16::from(tm.min) << TIME_MIN_SHIFT)
        | u16::from(tm.sec >> SEC_GRANULARITY);
    let date = (year << DATE_YEAR_SHIFT)
        | (u16::from(tm.month) << DATE_MONTH_SHIFT)
        | u16::from(tm.day);
    // The centisecond byte spans TWO seconds, so it carries both the odd
    // second the time field rounded away and the sub-second remainder.
    let cs = (ts.sec & 1) as u8 * CS_PER_SEC + (ts.nsec / NSEC_PER_CS) as u8;
    FatTime { time, date, cs }
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

/// Whether a year counted from 1980 has a 29th of February. # C: O(1)
fn is_leap(year: i64) -> bool { year & 3 == 0 && year != YEAR_2100 }
