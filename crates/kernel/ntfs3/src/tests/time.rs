use super::*;
use vfs::timespec::Timespec64;

/// The NT count at the Unix epoch.
const AT_EPOCH: i64 = 11_644_473_600 * 10_000_000;

#[test]
fn the_unix_epoch_is_the_nt_epoch_plus_its_offset() {
    assert_eq!(to_unix(AT_EPOCH), Timespec64::new(0, 0));
    assert_eq!(from_unix(Timespec64::new(0, 0)), AT_EPOCH);
}

#[test]
fn an_instant_round_trips_through_both_directions() {
    let ts = Timespec64::new(1_700_000_000, 123_456_700);
    assert_eq!(to_unix(from_unix(ts)), ts);
}

#[test]
fn the_granularity_is_a_hundred_nanoseconds() {
    let ts = Timespec64::new(5, 199);
    // The stored count cannot name the last 99 nanoseconds, so they are
    // dropped rather than rounded up into the next second.
    assert_eq!(to_unix(from_unix(ts)), Timespec64::new(5, 100));
    assert_eq!(truncate(ts), Timespec64::new(5, 100));
}

#[test]
fn an_instant_before_the_unix_epoch_floors_rather_than_truncating() {
    // Reading the count as unsigned turns 1970 minus a second into a date
    // half a million years away.
    let before = AT_EPOCH - 10_000_000;
    assert_eq!(to_unix(before), Timespec64::new(-1, 0));
    let mid = AT_EPOCH - 5_000_000;
    let got = to_unix(mid);
    assert_eq!(got.sec, -1);
    assert_eq!(got.nsec, 500_000_000);
}

#[test]
fn a_count_of_zero_is_the_nt_epoch_not_the_unix_one() {
    assert_eq!(to_unix(0).sec, -11_644_473_600);
}
