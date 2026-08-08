use alloc::vec::Vec;

use super::*;

#[test]
fn a_stamp_names_the_second_the_millisecond_and_the_serial() {
    let mut v = Vec::new();
    stamp(&mut v, 1_712_000_000, 42, 7);
    assert_eq!(v, b"audit(1712000000.042:7): ");
}

/// The millisecond field is three digits even when the value is small: a
/// consumer reads it positionally.
#[test]
fn the_millisecond_field_is_zero_padded() {
    let mut v = Vec::new();
    stamp(&mut v, 0, 5, 1);
    assert_eq!(v, b"audit(0.005:1): ");
}

#[test]
fn a_record_is_its_stamp_followed_by_its_body() {
    let r = build(1331, 3_000_000_000, 9, b"resp=1");
    assert_eq!(r.ty, 1331);
    assert_eq!(r.text, b"audit(3.000:9): resp=1");
    assert_eq!(r.len(), r.text.len());
    assert!(!r.is_empty());
}

/// Nanoseconds truncate toward the millisecond, never round: two records in
/// the same millisecond must carry the same stamp so their serials order them.
#[test]
fn sub_millisecond_time_truncates() {
    let a = build(1, 1_999_999, 1, b"x");
    let b = build(1, 1_000_001, 2, b"x");
    assert_eq!(a.text, b"audit(0.001:1): x");
    assert_eq!(b.text, b"audit(0.001:2): x");
}

#[test]
fn serials_are_allocated_strictly_increasing_and_never_zero() {
    // Concurrent tests share the counter, so the guarantee under test is
    // "later is greater", not "later is one more".
    let first = next_serial();
    let second = next_serial();
    assert_ne!(first, 0);
    assert!(second > first, "{first} -> {second}");
}
