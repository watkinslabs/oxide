//! Calendar arithmetic: a second count as a date.
//!
//! The proleptic Gregorian calendar, by the shifted-era method: the year is
//! taken to start in March so the leap day lands at the end of it and the
//! month lengths become a repeating pattern, which removes every table and
//! every special case for February.

/// A second count broken into the fields a date is written with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CivilTime {
    /// Absolute year, not an offset from any epoch.
    pub year: i32,
    /// 1-12.
    pub month: u8,
    /// 1-31.
    pub day: u8,
    pub hour: u8,
    pub min: u8,
    pub sec: u8,
}

const SECS_PER_MIN: i64 = 60;
const SECS_PER_HOUR: i64 = 3600;
const SECS_PER_DAY: i64 = 86400;

/// Days from 1970-01-01 to 0000-03-01, the shifted calendar's origin.
const ERA_SHIFT: i64 = 719_468;
/// Days in a 400-year era, and the years in one.
const DAYS_PER_ERA: i64 = 146_097;
const YEARS_PER_ERA: i64 = 400;

/// A second count relative to the Unix epoch, as a date.
///
/// Negative counts floor rather than truncate: a time before the epoch is
/// hours before a day boundary, not hours after it, and truncating would put
/// it on the wrong day.
/// # C: O(1)
pub fn from_unix_seconds(secs: i64) -> CivilTime {
    let days = secs.div_euclid(SECS_PER_DAY);
    let rem = secs.rem_euclid(SECS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    CivilTime {
        year,
        month,
        day,
        hour: (rem / SECS_PER_HOUR) as u8,
        min: ((rem % SECS_PER_HOUR) / SECS_PER_MIN) as u8,
        sec: (rem % SECS_PER_MIN) as u8,
    }
}

/// A day count relative to the Unix epoch, as year, month and day. # C: O(1)
fn civil_from_days(days: i64) -> (i32, u8, u8) {
    let z = days + ERA_SHIFT;
    let era = if z >= 0 { z } else { z - (DAYS_PER_ERA - 1) } / DAYS_PER_ERA;
    let doe = z - era * DAYS_PER_ERA;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * YEARS_PER_ERA;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    ((y + i64::from(m <= 2)) as i32, m as u8, d as u8)
}
