//! The EIR walk. The bound checks are the ones that matter: a field claiming
//! more bytes than remain must end the walk, not read what follows the buffer.

use super::*;
use crate::uapi::hci::{EIR_FLAGS, EIR_NAME_COMPLETE, EIR_TX_POWER};

#[test]
fn append_then_walk_round_trips() {
    let mut buf = alloc::vec::Vec::new();
    assert!(append_data(&mut buf, EIR_FLAGS, &[0x06]));
    assert!(append_data(&mut buf, EIR_NAME_COMPLETE, b"oxide"));
    append_le16(&mut buf, 0x19, 0x0340);
    let fields: alloc::vec::Vec<_> = EirIter::new(&buf).collect();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0], (EIR_FLAGS, &[0x06][..]));
    assert_eq!(fields[1], (EIR_NAME_COMPLETE, &b"oxide"[..]));
    assert_eq!(fields[2], (0x19, &[0x40, 0x03][..]));
    assert_eq!(get_data(&buf, EIR_NAME_COMPLETE), Some(&b"oxide"[..]));
    assert_eq!(get_data(&buf, EIR_TX_POWER), None);
}

#[test]
fn a_field_length_counts_its_type_byte() {
    let mut buf = alloc::vec::Vec::new();
    append_data(&mut buf, EIR_FLAGS, &[0xaa, 0xbb]);
    assert_eq!(buf[0], 3);
    assert_eq!(buf.len(), precalc_len(2));
}

#[test]
fn a_zero_length_terminates_the_walk() {
    // Two good fields, a zero terminator, then bytes that would parse as a
    // third field if the terminator were ignored.
    let buf = [2u8, EIR_FLAGS, 0x06, 2, EIR_TX_POWER, 0x00, 0x00, 2, EIR_FLAGS, 0x01];
    let fields: alloc::vec::Vec<_> = EirIter::new(&buf).collect();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[1].0, EIR_TX_POWER);
    assert!(is_well_formed(&buf));
}

/// A field claiming more bytes than remain ends the walk. Without the bound the
/// value slice would run past the buffer.
#[test]
fn a_field_claiming_more_than_remains_is_refused() {
    // One good field, then a field of length 9 with only three bytes left.
    let buf = [2u8, EIR_FLAGS, 0x06, 9, EIR_NAME_COMPLETE, 0x41, 0x42];
    let fields: alloc::vec::Vec<_> = EirIter::new(&buf).collect();
    assert_eq!(fields.len(), 1, "the overrunning field must not be yielded");
    assert_eq!(get_data(&buf, EIR_NAME_COMPLETE), None);
    assert!(!is_well_formed(&buf));
}

/// The same, one byte over — the off-by-one that a `>=` would let through.
#[test]
fn a_field_one_byte_too_long_is_refused() {
    let buf = [3u8, EIR_FLAGS, 0x06];
    assert_eq!(EirIter::new(&buf).count(), 0);
    // Exactly right is accepted.
    let buf = [2u8, EIR_FLAGS, 0x06];
    assert_eq!(EirIter::new(&buf).count(), 1);
}

#[test]
fn a_truncated_header_yields_nothing() {
    assert_eq!(EirIter::new(&[]).count(), 0);
    assert_eq!(EirIter::new(&[5]).count(), 0);
    assert!(is_well_formed(&[]));
    assert!(!is_well_formed(&[5]));
}

/// A field with a length of one carries no value. It is a real field to the
/// walk and an absent one to a lookup.
#[test]
fn an_empty_field_is_present_to_the_walk_and_absent_to_a_lookup() {
    let buf = [1u8, EIR_NAME_COMPLETE, 2, EIR_FLAGS, 0x06];
    let fields: alloc::vec::Vec<_> = EirIter::new(&buf).collect();
    assert_eq!(fields.len(), 2);
    assert!(fields[0].1.is_empty());
    assert_eq!(get_data(&buf, EIR_NAME_COMPLETE), None);
    assert_eq!(get_data(&buf, EIR_FLAGS), Some(&[0x06][..]));
}

#[test]
fn a_value_too_long_for_the_length_byte_is_refused() {
    let mut buf = alloc::vec::Vec::new();
    let big = alloc::vec![0u8; EIR_MAX_FIELD_DATA + 1];
    assert!(!append_data(&mut buf, EIR_FLAGS, &big));
    assert!(buf.is_empty(), "a refused append must write nothing");
    let ok = alloc::vec![0u8; EIR_MAX_FIELD_DATA];
    assert!(append_data(&mut buf, EIR_FLAGS, &ok));
    assert_eq!(buf[0], u8::MAX);
}

#[test]
fn service_data_is_found_by_uuid() {
    let mut buf = alloc::vec::Vec::new();
    append_data(&mut buf, EIR_SERVICE_DATA, &[0x0d, 0x18, 0xaa, 0xbb]);
    append_data(&mut buf, EIR_SERVICE_DATA, &[0x0f, 0x18, 0xcc]);
    assert_eq!(get_service_data(&buf, 0x180d), Some(&[0xaa, 0xbb][..]));
    assert_eq!(get_service_data(&buf, 0x180f), Some(&[0xcc][..]));
    assert_eq!(get_service_data(&buf, 0x1234), None);
}

/// A service-data field too short to hold a UUID is skipped rather than read.
#[test]
fn a_short_service_data_field_is_skipped() {
    let buf = [2u8, EIR_SERVICE_DATA, 0x0d];
    assert_eq!(get_service_data(&buf, 0x180d), None);
}
