//! A token service reads a BOOLEAN as a byte and a ULONG as a half.

use super::*;

#[test]
fn a_boolean_is_the_low_byte_of_its_slot() {
    assert!(boolean(1));
    assert!(!boolean(0));
    // The slot's upper half carries whatever it held before the caller's
    // byte-wide store; a TRUE spelled that way is still TRUE.
    assert!(boolean(0x7fff_0000_0000_0001));
    assert!(boolean(0xdead_beef_dead_be01));
}

#[test]
fn a_boolean_slot_whose_low_byte_is_zero_is_false() {
    assert!(!boolean(0x0000_0000_0000_0100));
    assert!(!boolean(0xffff_ffff_ffff_ff00));
}

#[test]
fn a_ulong_is_the_low_half_of_its_slot() {
    assert_eq!(ulong(4), 4);
    assert_eq!(ulong(0x7fff_0000_0000_0004), 4);
    assert_eq!(ulong(0xffff_ffff_0000_0000), 0);
    assert_eq!(ulong(0x0000_0000_ffff_ffff), u32::MAX);
}

#[test]
fn a_token_type_is_admitted_by_its_low_half_alone() {
    assert!(duplicate_type_admitted(TOKEN_PRIMARY as u64));
    assert!(duplicate_type_admitted(TOKEN_IMPERSONATION as u64));
    assert!(duplicate_type_admitted(0x1234_5678_0000_0001));
    assert!(!duplicate_type_admitted(0));
    assert!(!duplicate_type_admitted(3));
}
