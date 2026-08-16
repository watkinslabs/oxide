use super::*;
use crate::uapi::{REC_OFF_FIX_NUM, REC_OFF_FIX_OFF, SECTOR_BYTES};

/// A two-sector structure with its array at 0x30, as a formatter writes one.
fn structure() -> alloc::vec::Vec<u8> {
    let mut b = alloc::vec![0u8; SECTOR_BYTES * 2];
    b[REC_OFF_FIX_OFF..REC_OFF_FIX_OFF + 2].copy_from_slice(&0x30u16.to_le_bytes());
    b[REC_OFF_FIX_NUM..REC_OFF_FIX_NUM + 2].copy_from_slice(&3u16.to_le_bytes());
    b
}

#[test]
fn a_sequence_round_trips_through_both_directions() {
    let mut b = structure();
    // Two bytes at the end of each sector that the sequence must preserve.
    b[SECTOR_BYTES - 2] = 0xAB;
    b[SECTOR_BYTES - 1] = 0xCD;
    b[SECTOR_BYTES * 2 - 2] = 0x12;
    b[SECTOR_BYTES * 2 - 1] = 0x34;
    let original = b.clone();
    pre_write(&mut b, 0x1122).unwrap();
    // Every sector now ends in the sequence value, and the real bytes are in
    // the array.
    assert_eq!(&b[SECTOR_BYTES - 2..SECTOR_BYTES], &0x1122u16.to_le_bytes());
    assert_eq!(&b[SECTOR_BYTES * 2 - 2..SECTOR_BYTES * 2], &0x1122u16.to_le_bytes());
    post_read(&mut b, false).unwrap();
    assert_eq!(b[SECTOR_BYTES - 2..SECTOR_BYTES], original[SECTOR_BYTES - 2..SECTOR_BYTES]);
    assert_eq!(b[SECTOR_BYTES * 2 - 2..], original[SECTOR_BYTES * 2 - 2..]);
}

#[test]
fn a_torn_write_is_detected() {
    // One sector written from a different write than the rest: its tail does
    // not carry the sequence value.
    let mut b = structure();
    pre_write(&mut b, 0x1122).unwrap();
    b[SECTOR_BYTES * 2 - 1] = 0xFF;
    assert_eq!(post_read(&mut b, false), Err(FixupError::Torn));
}

#[test]
fn an_array_reaching_past_the_first_sector_is_refused() {
    let mut b = structure();
    b[REC_OFF_FIX_OFF..REC_OFF_FIX_OFF + 2].copy_from_slice(&(SECTOR_BYTES as u16 - 2).to_le_bytes());
    assert_eq!(post_read(&mut b, false), Err(FixupError::Corrupt));
}

#[test]
fn an_unaligned_array_is_refused() {
    let mut b = structure();
    b[REC_OFF_FIX_OFF..REC_OFF_FIX_OFF + 2].copy_from_slice(&0x31u16.to_le_bytes());
    assert_eq!(post_read(&mut b, false), Err(FixupError::Corrupt));
}

#[test]
fn a_count_covering_more_sectors_than_there_are_is_refused() {
    let mut b = structure();
    b[REC_OFF_FIX_NUM..REC_OFF_FIX_NUM + 2].copy_from_slice(&9u16.to_le_bytes());
    assert_eq!(post_read(&mut b, false), Err(FixupError::Corrupt));
}

#[test]
fn a_count_of_zero_is_refused() {
    let mut b = structure();
    b[REC_OFF_FIX_NUM..REC_OFF_FIX_NUM + 2].copy_from_slice(&0u16.to_le_bytes());
    assert_eq!(post_read(&mut b, false), Err(FixupError::Corrupt));
}

#[test]
fn the_simple_form_derives_the_count_from_the_length() {
    let mut b = structure();
    // A count the header gets wrong; the simple form ignores it.
    b[REC_OFF_FIX_NUM..REC_OFF_FIX_NUM + 2].copy_from_slice(&99u16.to_le_bytes());
    assert!(post_read(&mut b, true).is_ok());
}

#[test]
fn the_sequence_never_lands_on_a_value_an_unwritten_sector_would_have() {
    // A sector of zeros or of ones is what a device returns for a block it
    // never wrote, so either would make one read as whole.
    assert_eq!(next_sample(0xFFFE), 1);
    assert_eq!(next_sample(0xFFFF), 1);
    assert_eq!(next_sample(1), 2);
    assert_ne!(next_sample(0), 0);
}
