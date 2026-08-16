//! The origin record, as bytes.

extern crate alloc;

use alloc::vec;
use syscall::errno::Errno;

use crate::uapi::{FB_HEADER_LEN, FH_FLAG_ANY_ENDIAN, FH_MAGIC};

use super::{check, decode, encode, from_index_name, index_name, same, FhError};

/// A layer identity, distinct enough that a mismatch shows.
const UUID: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

#[test]
fn a_record_round_trips() {
    let raw = encode(0x81, UUID, &[0xde, 0xad, 0xbe, 0xef], false).unwrap();
    let fh = decode(&raw).unwrap();
    assert_eq!(fh.fid_type, 0x81);
    assert_eq!(fh.uuid, UUID);
    assert_eq!(fh.fid, vec![0xde, 0xad, 0xbe, 0xef]);
    assert!(!fh.is_upper);
}

#[test]
fn the_upper_flag_survives() {
    let raw = encode(1, UUID, &[9], true).unwrap();
    assert!(decode(&raw).unwrap().is_upper);
}

#[test]
fn the_length_byte_covers_the_whole_record() {
    let raw = encode(1, UUID, &[1, 2, 3], false).unwrap();
    assert_eq!(raw[2] as usize, raw.len());
    assert_eq!(raw.len(), FB_HEADER_LEN + 3);
}

#[test]
fn a_short_buffer_is_invalid() {
    assert_eq!(check(&[0; 4]), Err(FhError::Invalid));
}

#[test]
fn a_length_longer_than_what_was_read_is_invalid() {
    let mut raw = encode(1, UUID, &[1, 2, 3], false).unwrap();
    raw[2] = 200;
    assert_eq!(check(&raw), Err(FhError::Invalid));
}

#[test]
fn a_foreign_magic_is_invalid() {
    let mut raw = encode(1, UUID, &[1], false).unwrap();
    raw[1] = FH_MAGIC ^ 0xff;
    assert_eq!(check(&raw), Err(FhError::Invalid));
}

#[test]
fn a_newer_version_means_origin_unknown_not_corruption() {
    let mut raw = encode(1, UUID, &[1], false).unwrap();
    raw[0] = 1;
    assert_eq!(check(&raw), Err(FhError::Unknown));
    assert_eq!(FhError::Unknown.errno(), Errno::Enodata);
}

#[test]
fn an_unknown_flag_means_origin_unknown() {
    let mut raw = encode(1, UUID, &[1], false).unwrap();
    raw[3] |= 1 << 7;
    assert_eq!(check(&raw), Err(FhError::Unknown));
}

#[test]
fn the_other_byte_order_means_origin_unknown() {
    let mut raw = encode(1, UUID, &[1], false).unwrap();
    raw[3] ^= crate::uapi::FH_FLAG_BIG_ENDIAN;
    assert_eq!(check(&raw), Err(FhError::Unknown));
}

#[test]
fn an_endian_neutral_record_is_read_either_way() {
    let mut raw = encode(1, UUID, &[1], false).unwrap();
    raw[3] |= FH_FLAG_ANY_ENDIAN | crate::uapi::FH_FLAG_BIG_ENDIAN;
    assert!(check(&raw).is_ok());
}

#[test]
fn two_records_for_one_object_compare_equal_past_the_length() {
    let a = encode(1, UUID, &[7, 7], false).unwrap();
    let mut b = a.clone();
    b.extend_from_slice(&[0xff, 0xff]);
    assert!(same(&a, &b));
}

#[test]
fn two_records_for_different_objects_differ() {
    let a = encode(1, UUID, &[7], false).unwrap();
    let b = encode(1, UUID, &[8], false).unwrap();
    assert!(!same(&a, &b));
}

#[test]
fn the_index_name_round_trips() {
    let raw = encode(0x0f, UUID, &[0xa0, 0x0b], false).unwrap();
    let name = index_name(&raw).unwrap();
    assert!(name.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    assert_eq!(from_index_name(&name).unwrap(), raw);
}

#[test]
fn a_name_too_short_to_be_a_record_is_refused() {
    assert_eq!(from_index_name("abcd"), Err(Errno::Einval));
}

#[test]
fn an_odd_or_non_hex_name_is_refused() {
    let raw = encode(1, UUID, &[1], false).unwrap();
    let mut name = index_name(&raw).unwrap();
    name.push('z');
    assert_eq!(from_index_name(&name), Err(Errno::Einval));
    name.push('z');
    assert_eq!(from_index_name(&name), Err(Errno::Einval));
}
