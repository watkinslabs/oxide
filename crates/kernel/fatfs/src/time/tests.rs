//! Timestamp conversion, both directions, against the vectors that pin the
//! reference's own arithmetic.
//!
//! The dates were chosen because each one breaks a different naive
//! implementation: the two ends of the representable range, three leap-year
//! rules (divisible by four, by four hundred, by one hundred but not four
//! hundred), an odd second the two-second field cannot hold, and an offset
//! large enough to move a reading across a year boundary in each direction.

use super::*;

/// A mount that named an offset of `minutes`.
fn tz(minutes: i32) -> TimeConfig { TimeConfig::with_offset(minutes) }

/// (name, unix seconds, unix nanoseconds, time, date, cs, offset minutes).
///
/// Both directions must reproduce every row: these are exact round trips, not
/// one-way conversions.
const ROUND_TRIP: &[(&str, i64, u32, u16, u16, u8, i32)] = &[
    ("earliest representable, UTC (1980-01-01 00:00:00)", 315532800, 0, 0, 33, 0, 0),
    ("latest representable, UTC (2107-12-31 23:59:58)", 4354819198, 0, 49021, 65439, 0, 0),
    ("earliest representable, offset 11h", 315493200, 0, 0, 33, 0, 11 * 60),
    ("latest representable, offset -11h", 4354858798, 0, 49021, 65439, 0, -11 * 60),
    ("leap day of a year divisible by four (1996-02-29)", 825552000, 0, 0, 8285, 0, 0),
    ("2000 IS a leap year (2000-02-29)", 951782400, 0, 0, 10333, 0, 0),
    ("2100 is NOT a leap year (2100-03-01)", 4107542400, 0, 0, 61537, 0, 0),
    ("leap day, offset -1h (2004-02-29 00:30 UTC)", 1078014600, 0, 48064, 12380, 0, -60),
    ("leap day, offset +1h (2004-02-29 23:30 UTC)", 1078097400, 0, 960, 12385, 0, 60),
    ("odd second, carried by the centisecond byte", 946684799, 0, 49021, 10143, 100, 0),
    ("ten milliseconds", 315532800, 10000000, 0, 33, 1, 0),
];

#[test]
fn every_vector_converts_from_the_stored_fields() {
    for (name, sec, nsec, time, date, cs, offset) in ROUND_TRIP.iter().copied() {
        let got = to_unix(&tz(offset), FatTime { time, date, cs });
        assert_eq!(got.sec, sec, "{name}: seconds");
        assert_eq!(got.nsec, nsec, "{name}: nanoseconds");
    }
}

#[test]
fn every_vector_converts_back_into_the_stored_fields() {
    for (name, sec, nsec, time, date, cs, offset) in ROUND_TRIP.iter().copied() {
        let got = from_unix(&tz(offset), Timespec64::new(sec, nsec));
        assert_eq!(got, FatTime { time, date, cs }, "{name}");
    }
}

/// (name, unix seconds, time, date, cs, offset minutes).
const CLAMPED: &[(&str, i64, u16, u16, u8, i32)] = &[
    ("one second before the epoch the format starts at", 315532799, 0, 33, 0, 0),
    ("an offset pushes a 1980 reading below the epoch", 315534600, 0, 33, 0, -60),
    ("one second past the last representable second", 4354819200, 49021, 65439, 199, 0),
    ("an offset pushes a 2107 reading past the end", 4354817400, 49021, 65439, 199, 60),
];

/// A date the seven-bit year cannot name does not wrap.
///
/// Wrapping is the failure this pins: 1979 stored as year 127 would read back
/// as 2107, so a file older than the format would sort as the newest thing on
/// the medium.
#[test]
fn out_of_range_dates_clamp_to_the_end_they_passed() {
    for (name, sec, time, date, cs, offset) in CLAMPED.iter().copied() {
        let got = from_unix(&tz(offset), Timespec64::from_secs(sec));
        assert_eq!(got, FatTime { time, date, cs }, "{name}");
    }
}

/// (name, unix seconds, nanoseconds, expected seconds, offset minutes).
const ATIME: &[(&str, i64, u32, i64, i32)] = &[
    ("UTC midnight", 1078058096, 789000000, 1078012800, 0),
    ("offset -1h moves the boundary back a day", 1078014645, 123000000, 1077930000, -60),
    ("offset +1h moves it forward", 1078097445, 123000000, 1078095600, 60),
];

/// The access time has a date and no time of day, so it lands on the previous
/// LOCAL midnight — which is not the previous UTC midnight whenever the mount
/// names an offset.
#[test]
fn the_access_time_truncates_to_the_local_day() {
    for (name, sec, nsec, want, offset) in ATIME.iter().copied() {
        let got = truncate_atime(&tz(offset), Timespec64::new(sec, nsec));
        assert_eq!(got, Timespec64::from_secs(want), "{name}");
    }
}

/// The modification field counts seconds in twos, so an odd second is not
/// storable and must be truncated in memory too — otherwise a program that
/// writes a file and stats it sees a time that changes at the next mount.
#[test]
fn the_modification_time_truncates_to_two_seconds() {
    assert_eq!(truncate_mtime(Timespec64::new(946684799, 500000000)),
               Timespec64::from_secs(946684798));
    assert_eq!(truncate_mtime(Timespec64::new(946684798, 0)),
               Timespec64::from_secs(946684798), "an even second is already storable");
}

/// A mount that named no offset reads the medium as UTC.
#[test]
fn no_offset_reads_the_stored_reading_as_utc() {
    let cfg = TimeConfig::default();
    assert_eq!(to_unix(&cfg, FatTime { time: 0, date: 33, cs: 0 }).sec, 315532800);
}

/// A corrupt record can name month zero or day zero, which no calendar has.
/// The reference reads it as the first of the month rather than refusing the
/// entry, because refusing would hide every name in the directory behind it.
#[test]
fn a_zero_month_or_day_reads_as_the_first() {
    let cfg = TimeConfig::default();
    let zero = to_unix(&cfg, FatTime { time: 0, date: 0, cs: 0 });
    let first = to_unix(&cfg, FatTime { time: 0, date: 33, cs: 0 });
    assert_eq!(zero, first, "a wholly zero date is the epoch the format starts at");
}

/// The centisecond byte spans two seconds: a value at or above 100 carries
/// the odd second the time field could not.
#[test]
fn the_centisecond_byte_carries_the_odd_second() {
    let cfg = TimeConfig::default();
    let even = to_unix(&cfg, FatTime { time: 0, date: 33, cs: 99 });
    let odd = to_unix(&cfg, FatTime { time: 0, date: 33, cs: CS_MAX });
    assert_eq!(even.sec, 315532800);
    assert_eq!(even.nsec, 990000000);
    assert_eq!(odd.sec, 315532801, "the second half of the byte's range is the next second");
    assert_eq!(odd.nsec, 990000000);
}
