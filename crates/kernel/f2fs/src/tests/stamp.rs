//! The stored timestamp pair as the interface's instant.

use super::*;

#[test]
fn a_stored_pair_carries_through_unchanged() {
    let t = stamp((1_700_000_000, 123_456_789));
    assert_eq!(t.sec, 1_700_000_000);
    assert_eq!(t.nsec, 123_456_789);
}

#[test]
fn the_epoch_carries_through() {
    let t = stamp((0, 0));
    assert_eq!((t.sec, t.nsec), (0, 0));
}

#[test]
fn a_pre_epoch_instant_stays_negative_rather_than_clamping_to_zero() {
    // The seconds are unsigned on the medium and signed at the interface; a
    // restored archive from before 1970 depends on this.
    let stored = (-1000i64) as u64;
    assert_eq!(stamp((stored, 0)).sec, -1000);
}

#[test]
fn a_sub_second_field_at_its_maximum_does_not_carry() {
    let t = stamp((5, 999_999_999));
    assert_eq!((t.sec, t.nsec), (5, 999_999_999));
}

#[test]
fn an_out_of_range_sub_second_field_carries_into_the_seconds() {
    let t = stamp((5, 1_500_000_000));
    assert_eq!(t.sec, 6);
    assert_eq!(t.nsec, 500_000_000);
}

#[test]
fn two_stamps_order_by_seconds_then_by_the_sub_second_field() {
    assert!(stamp((5, 0)) < stamp((5, 1)));
    assert!(stamp((5, 999_999_999)) < stamp((6, 0)));
    assert!(stamp((-1i64 as u64, 0)) < stamp((0, 0)));
}
