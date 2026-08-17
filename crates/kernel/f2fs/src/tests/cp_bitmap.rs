//! Where the two version bitmaps live, in each of the three layouts.
//!
//! Reading a bitmap at the wrong offset never fails — it selects the other
//! copy of every table block and returns a whole checkpoint's worth of stale
//! addresses. These tests pin each layout's offsets numerically.

use super::*;
use crate::checkpoint::{parse, Pack};
use crate::test_image::meta::put32;
use crate::uapi::*;
use alloc::vec;
use alloc::vec::Vec;

const NAT_LEN: u32 = 64;
const SIT_LEN: u32 = 48;

/// A checkpoint header carrying the two bitmap widths and `flags`.
fn cp(flags: u32) -> Checkpoint {
    let mut c = vec![0u8; BLKSIZE];
    put32(&mut c, CP_CKPT_FLAGS, flags);
    put32(&mut c, CP_NAT_VER_BITMAP_BYTESIZE, NAT_LEN);
    put32(&mut c, CP_SIT_VER_BITMAP_BYTESIZE, SIT_LEN);
    parse(&c, Pack::First).unwrap()
}

/// A joined buffer whose bytes name their own offset, so a slice's contents
/// prove where it was taken from.
fn marked(blocks: usize) -> Vec<u8> {
    (0..BLKSIZE * blocks).map(|i| (i % 251) as u8).collect()
}

#[test]
fn without_the_flag_and_without_payload_sit_comes_first() {
    let c = cp(0);
    assert_eq!(sit_offset(&c, 0), CP_SIT_NAT_VERSION_BITMAP);
    assert_eq!(nat_offset(&c, 0), CP_SIT_NAT_VERSION_BITMAP + SIT_LEN as usize);
}

#[test]
fn with_the_large_flag_a_guard_word_precedes_both_and_nat_comes_first() {
    // The guard word is the checksum itself, which is what lets the sum cover
    // both bitmaps. Ignoring it shifts every bit by four bytes.
    let c = cp(CP_LARGE_NAT_BITMAP_FLAG);
    assert_eq!(nat_offset(&c, 0), CP_SIT_NAT_VERSION_BITMAP + 4);
    assert_eq!(sit_offset(&c, 0), CP_SIT_NAT_VERSION_BITMAP + 4 + NAT_LEN as usize);
}

#[test]
fn with_payload_and_no_flag_nat_starts_at_the_area_and_sit_at_the_next_block() {
    let c = cp(0);
    assert_eq!(nat_offset(&c, 1), CP_SIT_NAT_VERSION_BITMAP);
    assert_eq!(sit_offset(&c, 1), BLKSIZE);
}

#[test]
fn the_large_flag_overrides_the_payload_layout() {
    let c = cp(CP_LARGE_NAT_BITMAP_FLAG);
    assert_eq!(nat_offset(&c, 3), CP_SIT_NAT_VERSION_BITMAP + 4);
    assert_eq!(sit_offset(&c, 3), CP_SIT_NAT_VERSION_BITMAP + 4 + NAT_LEN as usize);
}

#[test]
fn the_three_layouts_disagree_with_one_another() {
    // If two of them coincided, a test passing under one would say nothing
    // about the other.
    let plain = cp(0);
    let large = cp(CP_LARGE_NAT_BITMAP_FLAG);
    assert_ne!(nat_offset(&plain, 0), nat_offset(&large, 0));
    assert_ne!(nat_offset(&plain, 0), nat_offset(&plain, 1));
    assert_ne!(sit_offset(&plain, 0), sit_offset(&plain, 1));
    assert_ne!(sit_offset(&plain, 0), sit_offset(&large, 0));
}

#[test]
fn the_slices_come_from_the_offsets_the_layout_names() {
    let c = cp(0);
    let buf = marked(1);
    let nat = nat_bitmap(&c, &buf, 0).unwrap();
    let at = nat_offset(&c, 0);
    assert_eq!(nat.len(), NAT_LEN as usize);
    assert_eq!(nat, &buf[at..at + NAT_LEN as usize]);
    let sit = sit_bitmap(&c, &buf, 0).unwrap();
    assert_eq!(sit.len(), SIT_LEN as usize);
    assert_eq!(sit, &buf[CP_SIT_NAT_VERSION_BITMAP..CP_SIT_NAT_VERSION_BITMAP + SIT_LEN as usize]);
}

#[test]
fn the_two_bitmaps_do_not_overlap_in_any_layout() {
    for (c, payload) in [(cp(0), 0u32), (cp(0), 1), (cp(CP_LARGE_NAT_BITMAP_FLAG), 0)] {
        let n = nat_offset(&c, payload)..nat_offset(&c, payload) + NAT_LEN as usize;
        let s = sit_offset(&c, payload)..sit_offset(&c, payload) + SIT_LEN as usize;
        assert!(n.end <= s.start || s.end <= n.start, "overlap at payload {payload}");
    }
}

#[test]
fn a_bitmap_running_past_the_buffer_is_reported_rather_than_truncated() {
    let c = cp(0);
    let short = vec![0u8; 200];
    assert!(nat_bitmap(&c, &short, 0).is_none());
}

#[test]
fn a_payload_layouts_sit_bitmap_reads_out_of_the_payload_block() {
    let c = cp(0);
    let buf = marked(2);
    let sit = sit_bitmap(&c, &buf, 1).unwrap();
    assert_eq!(sit, &buf[BLKSIZE..BLKSIZE + SIT_LEN as usize]);
}

#[test]
fn a_payload_layout_with_only_one_block_cannot_reach_its_sit_bitmap() {
    let c = cp(0);
    let buf = marked(1);
    assert!(sit_bitmap(&c, &buf, 1).is_none());
}

#[test]
fn test_bit_counts_from_the_low_bit_of_byte_zero() {
    let map = [0b0000_0101u8, 0b1000_0000];
    assert!(test_bit(&map, 0));
    assert!(!test_bit(&map, 1));
    assert!(test_bit(&map, 2));
    assert!(!test_bit(&map, 14));
    assert!(test_bit(&map, 15));
}

#[test]
fn a_bit_past_the_bitmap_reads_as_clear() {
    // A bitmap narrower than the table means the tail was never versioned, and
    // the first copy is where those entries are.
    assert!(!test_bit(&[0xFFu8], 8));
    assert!(!test_bit(&[], 0));
}
