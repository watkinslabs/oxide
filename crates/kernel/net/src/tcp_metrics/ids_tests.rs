//! Metric slot numbering and the ABI attributes that name it.

use super::*;

#[test]
fn the_attribute_number_of_a_slot_is_its_index_plus_one() {
    assert_eq!(attr(RTT), 1);
    assert_eq!(attr(RTTVAR), 2);
    assert_eq!(attr(SSTHRESH), 3);
    assert_eq!(attr(CWND), 4);
    assert_eq!(attr(REORDERING), 5);
    // The two microsecond attributes continue the same numbering without
    // taking slots of their own.
    assert_eq!(ATTR_RTT_US, attr(REORDERING) + 1);
    assert_eq!(ATTR_RTTVAR_US, ATTR_RTT_US + 1);
    assert_eq!(COUNT, 5);
}

#[test]
fn a_held_microsecond_value_never_reports_as_no_metric() {
    assert_eq!(millis(0), 0, "an absent metric stays absent");
    assert_eq!(millis(1), 1, "a sub-millisecond metric reports the floor");
    assert_eq!(millis(999), 1);
    assert_eq!(millis(1000), 1);
    assert_eq!(millis(2500), 2);
}

#[test]
fn a_lock_bit_position_is_the_metric_index() {
    let lock = with_lock(with_lock(0, RTT), CWND);
    assert!(locked(lock, RTT));
    assert!(locked(lock, CWND));
    assert!(!locked(lock, RTTVAR));
    assert!(!locked(lock, SSTHRESH));
    assert!(!locked(lock, REORDERING));
    assert!(!locked(0, RTT));
    // A slot past the word cannot be pinned and never reads as pinned.
    assert_eq!(with_lock(0, 32), 0);
    assert!(!locked(u32::MAX, 32));
}
