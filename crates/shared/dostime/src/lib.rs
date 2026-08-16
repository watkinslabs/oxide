#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

//! The 1980-epoch date/time word pair, which FAT and exFAT both store.
//!
//! Two sixteen-bit words hold a LOCAL wall-clock reading: the date word packs
//! year-from-1980, month and day; the time word packs hour, minute and a
//! seconds field counting in twos. An extra byte carries centiseconds, which
//! spans two whole seconds and so also carries the odd second the time word
//! cannot name.
//!
//! The year field is seven bits, so the pair cannot represent anything before
//! 1980-01-01 or after 2107-12-31. Both ends CLAMP rather than wrap: a file
//! dated 1970 reads back as 1980, which is wrong by a decade and still
//! ordered, where a wrapped value would read as a date in the future.
//!
//! Nothing here knows about a filesystem. What each filesystem adds on top —
//! FAT's `tz=` mount option, exFAT's per-timestamp UTC-offset byte — is that
//! filesystem's own decision about which offset to pass in.
//!
//! Module manifest:
//! - `civil`: the calendar arithmetic both directions need.

pub(crate) mod civil;

pub use civil::CivilTime;

/// Seconds in the units the fields count in.
pub const SECS_PER_MIN: i64 = 60;
const SECS_PER_HOUR: i64 = 60 * 60;
pub const SECS_PER_DAY: i64 = SECS_PER_HOUR * 24;

/// Seconds between the Unix epoch and the 1980 epoch: ten years holding two
/// leap days.
const EPOCH_DELTA_DAYS: i64 = 365 * 10 + 2;

/// First and last year the seven-bit field can name.
pub const YEAR_MIN: i32 = 1980;
pub const YEAR_MAX: i32 = 2107;
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
/// name a month that does not exist, and it is read rather than rejected.
const DAYS_IN_YEAR: [i64; 16] = [0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 0, 0, 0];

/// The fields one stored timestamp occupies.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct DosTime {
    pub time: u16,
    pub date: u16,
    /// Centiseconds. Zero on a field that has no such byte.
    pub cs: u8,
}

/// A stored reading as a count of seconds and nanoseconds from the Unix
/// epoch, given the seconds to ADD to reach UTC.
///
/// Nothing here can fail: every bit pattern is a date, because the fields are
/// clamped up to a valid month and day rather than rejected. An entry another
/// system wrote with a zero date reads as the epoch the format starts at, not
/// as an error that would hide the whole directory.
/// # C: O(1)
pub fn to_unix(fields: DosTime, to_utc_secs: i64) -> (i64, u32) {
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
    second += to_utc_secs;

    if fields.cs != 0 {
        (second + i64::from(fields.cs / CS_PER_SEC), u32::from(fields.cs % CS_PER_SEC) * NSEC_PER_CS)
    } else {
        (second, 0)
    }
}

/// An instant as the fields that store it, given the seconds to ADD to a
/// stored reading to reach UTC.
///
/// Out of range at either end clamps to the end it passed. The centisecond
/// byte carries the odd second the two-second field cannot, which is why a
/// creation time can name an odd second and a modification time cannot.
/// # C: O(1)
pub fn from_unix(sec: i64, nsec: u32, to_utc_secs: i64) -> DosTime {
    let local = sec - to_utc_secs;
    let tm = civil::from_unix_seconds(local);

    if tm.year < YEAR_MIN { return DosTime { time: CLAMP_LOW_TIME, date: CLAMP_LOW_DATE, cs: 0 }; }
    if tm.year > YEAR_MAX {
        return DosTime { time: CLAMP_HIGH_TIME, date: CLAMP_HIGH_DATE, cs: CLAMP_HIGH_CS };
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
    let cs = (sec & 1) as u8 * CS_PER_SEC + (nsec / NSEC_PER_CS) as u8;
    DosTime { time, date, cs }
}

/// Whether a year counted from 1980 has a 29th of February. # C: O(1)
fn is_leap(year: i64) -> bool { year & 3 == 0 && year != YEAR_2100 }

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
