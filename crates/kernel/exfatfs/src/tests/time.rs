use super::*;
use crate::uapi::TZ_VALID;
use vfs::timespec::Timespec64;

/// 1980-01-01 00:00:00 UTC.
const EPOCH_1980: i64 = 315_532_800;
const QUARTER_HOUR: i64 = 15 * 60;

fn at_epoch(tz: u8) -> Stamp {
    Stamp { fields: DosTime { time: 0, date: (1 << 5) | 1, cs: 0 }, tz }
}

#[test]
fn a_byte_without_the_valid_bit_says_nothing() {
    assert_eq!(tz_to_utc(0), None);
    assert_eq!(tz_to_utc(0x04), None);
}

#[test]
fn a_zero_offset_with_the_valid_bit_means_utc() {
    assert_eq!(tz_to_utc(TZ_VALID), Some(0));
}

#[test]
fn the_field_counts_quarter_hours_ahead_of_utc() {
    // Two hours ahead: eight quarter-hours, so the instant is two hours
    // EARLIER than the same reading taken as UTC.
    assert_eq!(tz_to_utc(TZ_VALID | 8), Some(-8 * QUARTER_HOUR));
    assert_eq!(tz_to_utc(TZ_VALID | 0x3F), Some(-0x3F * QUARTER_HOUR));
}

#[test]
fn the_field_is_twos_complement_over_seven_bits() {
    // 0x40 is the most negative: sixteen hours behind UTC.
    assert_eq!(tz_to_utc(TZ_VALID | 0x40), Some(0x40 * QUARTER_HOUR));
    // 0x7F is one quarter-hour behind.
    assert_eq!(tz_to_utc(TZ_VALID | 0x7F), Some(QUARTER_HOUR));
}

#[test]
fn a_timestamps_own_offset_wins_over_the_mounts() {
    let cfg = TimeConfig::with_offset(600);
    // The reading says UTC, so the mount's ten-hour guess is not applied.
    assert_eq!(to_unix(&cfg, at_epoch(TZ_VALID)).sec, EPOCH_1980);
}

#[test]
fn a_timestamp_with_no_offset_falls_back_to_the_mounts() {
    let cfg = TimeConfig::with_offset(120);
    assert_eq!(to_unix(&cfg, at_epoch(0)).sec, EPOCH_1980 - 2 * 3600);
}

#[test]
fn a_timestamp_with_no_offset_and_no_mount_option_is_utc() {
    assert_eq!(to_unix(&TimeConfig::default(), at_epoch(0)).sec, EPOCH_1980);
}

fn test_timezone_minuteswest() -> i32 { 120 }

#[test]
fn sys_tz_uses_the_canonical_system_timezone_for_unknown_offsets() {
    vfs::inode_times::set_timezone_provider(test_timezone_minuteswest);
    let cfg = effective_config(TimeConfig::with_offset(600), true);
    assert_eq!(to_unix(&cfg, at_epoch(0)).sec, EPOCH_1980 + 2 * 3600);
    // A timestamp carrying its own valid offset still wins over sys_tz.
    assert_eq!(to_unix(&cfg, at_epoch(TZ_VALID)).sec, EPOCH_1980);
    vfs::inode_times::set_timezone_provider(|| 0);
}

#[test]
fn a_written_timestamp_says_utc_explicitly() {
    // The reading came from a clock with no timezone; claiming any other
    // offset would move every instant on the volume by that much.
    let stamp = from_unix(Timespec64::from_secs(EPOCH_1980 + 1234));
    assert_eq!(stamp.tz, TZ_VALID);
    assert_eq!(to_unix(&TimeConfig::default(), stamp).sec, EPOCH_1980 + 1234);
}

#[test]
fn a_written_timestamp_round_trips_under_any_mount_offset() {
    let cfg = TimeConfig::with_offset(-330);
    let stamp = from_unix(Timespec64::from_secs(EPOCH_1980 + 99_999));
    assert_eq!(to_unix(&cfg, stamp).sec, EPOCH_1980 + 99_999);
}

#[test]
fn the_access_timestamp_has_two_second_granularity() {
    assert_eq!(truncate_atime(Timespec64::new(EPOCH_1980 + 5, 500)).sec, EPOCH_1980 + 4);
    assert_eq!(truncate_atime(Timespec64::new(EPOCH_1980 + 5, 500)).nsec, 0);
}

#[test]
fn dropping_the_centisecond_byte_drops_the_odd_second() {
    let stamp = from_unix(Timespec64::new(EPOCH_1980 + 3, 250_000_000));
    assert_ne!(stamp.fields.cs, 0);
    let coarse = without_centiseconds(stamp);
    assert_eq!(coarse.fields.cs, 0);
    assert_eq!(to_unix(&TimeConfig::default(), coarse).sec, EPOCH_1980 + 2);
}
