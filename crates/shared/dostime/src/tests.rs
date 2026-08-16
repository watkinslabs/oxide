use super::*;

/// 1980-01-01 00:00:00 UTC.
const EPOCH_1980: i64 = 315_532_800;

#[test]
fn the_zero_pair_is_the_epoch_the_format_starts_at() {
    // A zero date names month 0 and day 0, which clamp up to the 1st of
    // January rather than reading as a date before the epoch.
    assert_eq!(to_unix(DosTime::default(), 0), (EPOCH_1980, 0));
}

#[test]
fn a_reading_round_trips_through_both_directions() {
    let fields = DosTime { time: (13 << 11) | (45 << 5) | 15, date: (44 << 9) | (7 << 5) | 19, cs: 0 };
    let (sec, _) = to_unix(fields, 0);
    assert_eq!(from_unix(sec, 0, 0), fields);
}

#[test]
fn the_seconds_field_counts_in_twos() {
    let (odd, _) = to_unix(DosTime { time: 1, date: CLAMP_LOW_DATE, cs: 0 }, 0);
    assert_eq!(odd, EPOCH_1980 + 2);
}

#[test]
fn the_centisecond_byte_carries_the_odd_second() {
    let fields = from_unix(EPOCH_1980 + 3, 0, 0);
    assert_eq!(fields.cs, 100);
    assert_eq!(to_unix(fields, 0), (EPOCH_1980 + 3, 0));
}

#[test]
fn the_centisecond_byte_carries_the_subsecond_remainder() {
    let fields = from_unix(EPOCH_1980, 250_000_000, 0);
    assert_eq!(fields.cs, 25);
    assert_eq!(to_unix(fields, 0), (EPOCH_1980, 250_000_000));
}

#[test]
fn a_date_before_the_epoch_clamps_up_rather_than_wrapping() {
    let fields = from_unix(0, 0, 0);
    assert_eq!(fields, DosTime { time: 0, date: (1 << 5) | 1, cs: 0 });
    assert_eq!(to_unix(fields, 0).0, EPOCH_1980);
}

#[test]
fn a_date_past_the_last_year_clamps_down_rather_than_wrapping() {
    let fields = from_unix(MAX_2107 + SECS_PER_DAY * 400, 0, 0);
    assert_eq!(fields.date >> 9, 127);
    assert!(to_unix(fields, 0).0 <= MAX_2107 + 2);
}

/// 2107-12-31 23:59:58 UTC.
const MAX_2107: i64 = 4_354_819_198;

#[test]
fn the_year_2100_is_not_a_leap_year() {
    // 2100-03-01, which is one day earlier than a naive divide-by-four rule
    // would place it.
    let fields = DosTime { time: 0, date: (120 << 9) | (3 << 5) | 1, cs: 0 };
    let (sec, _) = to_unix(fields, 0);
    assert_eq!(from_unix(sec, 0, 0), fields);
    let tm = CivilTime { year: 2100, month: 3, day: 1, hour: 0, min: 0, sec: 0 };
    assert_eq!(civil::from_unix_seconds(sec), tm);
}

#[test]
fn a_leap_day_in_range_round_trips() {
    let fields = DosTime { time: 0, date: (20 << 9) | (2 << 5) | 29, cs: 0 };
    let (sec, _) = to_unix(fields, 0);
    let tm = civil::from_unix_seconds(sec);
    assert_eq!((tm.year, tm.month, tm.day), (2000, 2, 29));
}

#[test]
fn an_offset_shifts_the_instant_a_reading_names() {
    let fields = DosTime { time: 0, date: (1 << 5) | 1, cs: 0 };
    // A medium written two hours ahead of UTC names an instant two hours
    // EARLIER than the same reading taken as UTC.
    assert_eq!(to_unix(fields, -2 * 3600).0, EPOCH_1980 - 2 * 3600);
    assert_eq!(from_unix(EPOCH_1980 - 2 * 3600, 0, -2 * 3600), fields);
}

#[test]
fn a_month_field_no_calendar_has_is_read_rather_than_rejected() {
    // Month 13 has no entry in the day table, so it contributes no days of
    // its own; 1980's leap day still counts, being a month past February.
    let fields = DosTime { time: 0, date: (13 << 5) | 1, cs: 0 };
    assert_eq!(to_unix(fields, 0).0, EPOCH_1980 + SECS_PER_DAY);
}
