//! The attribute region: one list assembled from two places.

use super::*;
use crate::test_image::nodes::dir::{xattr_entry, xattr_region};
use alloc::vec;
use alloc::vec::Vec;

fn attr(index: u8, name: &str, value: &str) -> (u8, Vec<u8>, Vec<u8>) {
    (index, name.as_bytes().to_vec(), value.as_bytes().to_vec())
}

#[test]
fn a_region_never_written_lists_nothing() {
    assert!(list(&[0u8; 256]).unwrap().is_empty());
    assert!(!has_header(&[0u8; 256]));
}

#[test]
fn a_written_region_carries_the_magic() {
    let r = xattr_region(256, &[]);
    assert!(has_header(&r));
    assert!(list(&r).unwrap().is_empty());
}

#[test]
fn one_attribute_reads_back_whole() {
    let r = xattr_region(256, &[attr(XATTR_INDEX_USER, "foo", "value")]);
    let l = list(&r).unwrap();
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].index, XATTR_INDEX_USER);
    assert_eq!(l[0].name, b"foo");
    assert_eq!(l[0].value, b"value");
}

#[test]
fn several_attributes_read_back_in_order() {
    let r = xattr_region(
        512,
        &[attr(XATTR_INDEX_USER, "a", "1"), attr(XATTR_INDEX_TRUSTED, "bb", "22"),
          attr(XATTR_INDEX_SECURITY, "ccc", "333")],
    );
    let l = list(&r).unwrap();
    assert_eq!(l.len(), 3);
    assert_eq!(l[1].name, b"bb");
    assert_eq!(l[2].value, b"333");
}

#[test]
fn a_record_is_aligned_up_to_a_four_byte_boundary() {
    // A record whose header, name and value sum to a non-multiple still ends
    // on a boundary; walking by the unaligned sum lands mid-record.
    assert_eq!(entry_size(3, 5), 12);
    assert_eq!(entry_size(1, 0), 8);
    assert_eq!(entry_size(4, 4), 12);
    assert_eq!(xattr_align(1), 4);
    assert_eq!(xattr_align(4), 4);
    assert_eq!(xattr_align(5), 8);
}

#[test]
fn a_record_needing_no_padding_is_not_padded() {
    let one = xattr_entry(XATTR_INDEX_USER, b"abcd", b"efgh");
    assert_eq!(one.len(), 12);
}

#[test]
fn the_list_ends_at_the_first_zeroed_header() {
    let mut r = xattr_region(512, &[attr(XATTR_INDEX_USER, "a", "1")]);
    // Anything past the terminator is not read.
    let past = XATTR_HEADER_SIZE + entry_size(1, 1) + 4;
    r[past] = XATTR_INDEX_USER;
    r[past + 1] = 1;
    assert_eq!(list(&r).unwrap().len(), 1);
}

#[test]
fn a_region_whose_records_run_past_the_end_is_an_error() {
    let mut r = xattr_region(64, &[attr(XATTR_INDEX_USER, "a", "1")]);
    // Claim a value far longer than the region.
    r[XATTR_HEADER_SIZE + XATTR_E_VALUE_SIZE..XATTR_HEADER_SIZE + XATTR_E_VALUE_SIZE + 2]
        .copy_from_slice(&9000u16.to_le_bytes());
    assert_eq!(list(&r), Err(XattrError::BadLength));
}

#[test]
fn a_region_ending_inside_a_record_is_an_error() {
    let mut r = xattr_region(64, &[attr(XATTR_INDEX_USER, "a", "1")]);
    r.truncate(XATTR_HEADER_SIZE + 2);
    assert_eq!(list(&r), Err(XattrError::Truncated));
}

#[test]
fn a_value_is_found_by_index_and_stored_name() {
    let r = xattr_region(256, &[attr(XATTR_INDEX_USER, "foo", "bar")]);
    assert_eq!(get(&r, XATTR_INDEX_USER, b"foo").unwrap(), Some(b"bar".to_vec()));
}

#[test]
fn the_same_name_under_another_index_is_a_different_attribute() {
    let r = xattr_region(
        256,
        &[attr(XATTR_INDEX_USER, "foo", "one"), attr(XATTR_INDEX_TRUSTED, "foo", "two")],
    );
    assert_eq!(get(&r, XATTR_INDEX_USER, b"foo").unwrap(), Some(b"one".to_vec()));
    assert_eq!(get(&r, XATTR_INDEX_TRUSTED, b"foo").unwrap(), Some(b"two".to_vec()));
}

#[test]
fn an_absent_name_reports_nothing() {
    let r = xattr_region(256, &[attr(XATTR_INDEX_USER, "foo", "bar")]);
    assert_eq!(get(&r, XATTR_INDEX_USER, b"baz").unwrap(), None);
}

#[test]
fn a_name_is_stored_without_its_prefix() {
    // Comparing the whole name would never match.
    let r = xattr_region(256, &[attr(XATTR_INDEX_USER, "foo", "bar")]);
    assert_eq!(list(&r).unwrap()[0].name, b"foo");
    assert_eq!(get(&r, XATTR_INDEX_USER, b"user.foo").unwrap(), None);
}

#[test]
fn a_listing_reports_the_prefixed_name() {
    let r = xattr_region(256, &[attr(XATTR_INDEX_USER, "foo", "bar")]);
    assert_eq!(list(&r).unwrap()[0].full_name().unwrap(), "user.foo");
}

#[test]
fn a_listing_is_zero_terminated_per_name() {
    let r = xattr_region(
        256,
        &[attr(XATTR_INDEX_USER, "a", "1"), attr(XATTR_INDEX_TRUSTED, "b", "2")],
    );
    assert_eq!(names(&r).unwrap(), b"user.a\0trusted.b\0".to_vec());
}

#[test]
fn an_index_with_no_exposed_prefix_is_skipped_from_a_listing() {
    let r = xattr_region(
        256,
        &[attr(XATTR_INDEX_ENCRYPTION, "c", "x"), attr(XATTR_INDEX_USER, "a", "1")],
    );
    assert_eq!(list(&r).unwrap().len(), 2);
    assert_eq!(names(&r).unwrap(), b"user.a\0".to_vec());
}

#[test]
fn a_callers_name_splits_into_an_index_and_the_remainder() {
    assert_eq!(split_name("user.foo"), Some((XATTR_INDEX_USER, b"foo".as_slice())));
    assert_eq!(split_name("trusted.x"), Some((XATTR_INDEX_TRUSTED, b"x".as_slice())));
    assert_eq!(split_name("security.selinux"),
               Some((XATTR_INDEX_SECURITY, b"selinux".as_slice())));
}

#[test]
fn the_access_control_names_have_no_separator_and_match_whole() {
    assert_eq!(split_name("system.posix_acl_access"),
               Some((XATTR_INDEX_POSIX_ACL_ACCESS, b"".as_slice())));
    assert_eq!(split_name("system.posix_acl_default"),
               Some((XATTR_INDEX_POSIX_ACL_DEFAULT, b"".as_slice())));
    assert_eq!(split_name("system.advise"), Some((XATTR_INDEX_ADVISE, b"".as_slice())));
}

#[test]
fn a_prefix_with_nothing_after_it_is_not_a_name() {
    assert_eq!(split_name("user."), None);
}

#[test]
fn a_name_under_no_known_prefix_is_refused() {
    assert_eq!(split_name("nosuch.foo"), None);
    assert_eq!(split_name("foo"), None);
}

#[test]
fn the_prefixes_are_what_the_format_defines() {
    assert_eq!(prefix_of(XATTR_INDEX_USER), Some("user."));
    assert_eq!(prefix_of(XATTR_INDEX_TRUSTED), Some("trusted."));
    assert_eq!(prefix_of(XATTR_INDEX_SECURITY), Some("security."));
    assert_eq!(prefix_of(XATTR_INDEX_LUSTRE), None);
    assert_eq!(prefix_of(XATTR_INDEX_VERITY), None);
}

#[test]
fn the_two_halves_are_joined_into_one_list() {
    // A record beginning in the inline part and continuing in the block is
    // lost if the two are searched separately.
    let inline_len = 40usize;
    let mut inline = xattr_region(inline_len, &[]);
    let long = xattr_entry(XATTR_INDEX_USER, b"spanning", &[7u8; 32]);
    // The record starts inside the inline part and runs past its end.
    let at = XATTR_HEADER_SIZE;
    inline.resize(at + long.len(), 0);
    inline[at..].copy_from_slice(&long);
    let block: Vec<u8> = inline.split_off(inline_len);
    let joined_area = joined(&inline, Some(&block));
    let l = list(&joined_area).unwrap();
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].name, b"spanning");
    assert_eq!(l[0].value, vec![7u8; 32]);
}

#[test]
fn joining_takes_only_the_blocks_attribute_bytes() {
    // The block's node footer is not part of the region; reading it as records
    // produces one with an enormous length.
    let inline = xattr_region(200, &[attr(XATTR_INDEX_USER, "a", "1")]);
    let block = vec![0xFFu8; BLKSIZE];
    let j = joined(&inline, Some(&block));
    assert_eq!(j.len(), 200 + VALID_XATTR_BLOCK_SIZE + 4);
}

#[test]
fn joining_without_a_block_still_pads_the_terminator() {
    let inline = xattr_region(200, &[]);
    let j = joined(&inline, None);
    assert_eq!(j.len(), 204);
    assert!(list(&j).unwrap().is_empty());
}

#[test]
fn a_region_full_to_its_last_byte_still_terminates() {
    // Without the padding word the terminator would fall outside the region.
    let mut inline = xattr_region(32, &[]);
    let e = xattr_entry(XATTR_INDEX_USER, b"ab", b"aa");
    assert_eq!(XATTR_HEADER_SIZE + e.len(), 32);
    inline[XATTR_HEADER_SIZE..].copy_from_slice(&e);
    let j = joined(&inline, None);
    assert_eq!(list(&j).unwrap().len(), 1);
}
