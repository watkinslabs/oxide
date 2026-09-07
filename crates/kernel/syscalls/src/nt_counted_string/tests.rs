//! Counted-string contracts: the descriptor layout, signed byte ordering,
//! case folding, the truncating copy and its terminator rule.

use super::rules::*;

#[test]
fn the_descriptor_places_two_counts_then_a_pointer() {
    assert_eq!(LENGTH_OFFSET, 0);
    assert_eq!(MAXIMUM_LENGTH_OFFSET, 2);
    assert_eq!(BUFFER_OFFSET, 8);
    assert_eq!(DESCRIPTOR_BYTES, 16);
    assert_eq!(UNIT_BYTES, 2);
}

#[test]
fn byte_ordering_reports_the_first_difference_then_the_length() {
    assert_eq!(compare_bytes(b"abc", b"abc", false), 0);
    assert_eq!(compare_bytes(b"abd", b"abc", false), 1);
    assert_eq!(compare_bytes(b"abc", b"abd", false), -1);
    // A shared prefix leaves only the length to separate them.
    assert_eq!(compare_bytes(b"abcd", b"ab", false), 2);
    assert_eq!(compare_bytes(b"ab", b"abcd", false), -2);
    assert_eq!(compare_bytes(b"", b"", false), 0);
}

#[test]
fn byte_characters_are_signed_so_high_bytes_order_below_ascii() {
    assert!(compare_bytes(&[0x80], b"a", false) < 0);
    assert!(compare_bytes(&[0xff], &[0x01], false) < 0);
    assert_eq!(compare_bytes(&[0xff], &[0xff], false), 0);
    // -1 minus 1 is the answer a signed subtraction gives, not 254.
    assert_eq!(compare_bytes(&[0xff], &[0x01], false), -2);
}

#[test]
fn the_case_fold_covers_the_unaccented_latin_letters_only() {
    assert_eq!(upper_byte(b'a' as i8), b'A' as i8);
    assert_eq!(upper_byte(b'z' as i8), b'Z' as i8);
    assert_eq!(upper_byte(b'A' as i8), b'A' as i8);
    assert_eq!(upper_byte(b'0' as i8), b'0' as i8);
    assert_eq!(upper_byte(b'{' as i8), b'{' as i8);
    assert_eq!(upper_byte(b'`' as i8), b'`' as i8);
    // 0xe4 is a lower-case letter in several code pages and is left alone.
    assert_eq!(upper_byte(0xe4u8 as i8), 0xe4u8 as i8);
    assert_eq!(compare_bytes(b"ABC", b"abc", true), 0);
    assert_ne!(compare_bytes(b"ABC", b"abc", false), 0);
    // Folding changes which side is greater, so it is not a no-op on order.
    assert!(compare_bytes(b"A", b"a", false) < 0);
    assert_eq!(compare_bytes(b"A", b"a", true), 0);
}

#[test]
fn the_unit_fold_lowers_the_unaccented_latin_letters_only() {
    assert_eq!(lower_unit(b'A' as u16), b'a' as u16);
    assert_eq!(lower_unit(b'Z' as u16), b'z' as u16);
    assert_eq!(lower_unit(b'a' as u16), b'a' as u16);
    assert_eq!(lower_unit(b'@' as u16), b'@' as u16);
    assert_eq!(lower_unit(b'[' as u16), b'[' as u16);
    assert_eq!(lower_unit(0x00c4), 0x00c4);
    assert_eq!(lower_unit(0x0410), 0x0410);
}

#[test]
fn a_copy_that_fits_terminates_and_one_that_fills_the_buffer_does_not() {
    assert_eq!(copy_plan(Some(6), 10), CopyPlan { bytes: 6, terminate: true });
    assert_eq!(copy_plan(Some(10), 10), CopyPlan { bytes: 10, terminate: false });
    assert_eq!(copy_plan(Some(0), 10), CopyPlan { bytes: 0, terminate: true });
    assert_eq!(copy_plan(Some(0), 0), CopyPlan { bytes: 0, terminate: false });
}

#[test]
fn a_copy_longer_than_the_buffer_truncates_rather_than_failing() {
    assert_eq!(copy_plan(Some(20), 10), CopyPlan { bytes: 10, terminate: false });
    assert_eq!(copy_plan(Some(11), 10), CopyPlan { bytes: 10, terminate: false });
}

#[test]
fn an_absent_source_empties_the_destination_without_touching_its_buffer() {
    assert_eq!(copy_plan(None, 10), CopyPlan { bytes: 0, terminate: false });
}

#[test]
fn the_terminator_lands_on_a_unit_boundary() {
    assert_eq!(terminator_offset(CopyPlan { bytes: 6, terminate: true }), 6);
    assert_eq!(terminator_offset(CopyPlan { bytes: 0, terminate: true }), 0);
    // An odd byte count cannot address half a unit, so it rounds down.
    assert_eq!(terminator_offset(CopyPlan { bytes: 7, terminate: true }), 6);
}

#[test]
fn unequal_lengths_settle_equality_before_any_content_is_read() {
    assert!(lengths_can_be_equal(8, 8));
    assert!(!lengths_can_be_equal(8, 6));
    assert!(!lengths_can_be_equal(0, 2));
    assert!(lengths_can_be_equal(0, 0));
}
