//! Which pack is current, and what makes one invalid.

use super::*;
use crate::checksum;
use crate::test_image::meta::{put32, put64};
use alloc::vec;
use alloc::vec::Vec;

/// A checkpoint block sealed at the block's end, with `version` and `blocks`.
fn cp_block(version: u64, blocks: u32) -> Vec<u8> {
    let mut c = vec![0u8; BLKSIZE];
    put64(&mut c, CP_CHECKPOINT_VER, version);
    put32(&mut c, CP_PACK_TOTAL_BLOCK_COUNT, blocks);
    put32(&mut c, CP_CHECKSUM_OFFSET_FIELD, CP_MAX_CHKSUM_OFFSET as u32);
    let crc = checksum::crc32(&c[..CP_MAX_CHKSUM_OFFSET]);
    put32(&mut c, CP_MAX_CHKSUM_OFFSET, crc);
    c
}

#[test]
fn a_matched_head_and_tail_validate() {
    let head = cp_block(5, 8);
    let tail = cp_block(5, 8);
    let cp = validate(&head, &tail, BLKS_PER_SEG, Pack::First).unwrap();
    assert_eq!(cp.version, 5);
    assert_eq!(cp.pack, Pack::First);
}

#[test]
fn a_tail_with_another_version_is_a_torn_write() {
    // The pack's atomicity IS this pairing: an interrupted checkpoint leaves
    // the head written and the tail not.
    let head = cp_block(5, 8);
    let tail = cp_block(4, 8);
    assert_eq!(validate(&head, &tail, BLKS_PER_SEG, Pack::First), Err(CpError::Torn));
}

#[test]
fn a_head_with_a_bad_checksum_is_rejected() {
    let mut head = cp_block(5, 8);
    head[CP_VALID_NODE_COUNT] ^= 0xFF;
    let tail = cp_block(5, 8);
    assert_eq!(validate(&head, &tail, BLKS_PER_SEG, Pack::First), Err(CpError::Checksum));
}

#[test]
fn a_tail_with_a_bad_checksum_is_rejected() {
    let head = cp_block(5, 8);
    let mut tail = cp_block(5, 8);
    tail[CP_VALID_NODE_COUNT] ^= 0xFF;
    assert_eq!(validate(&head, &tail, BLKS_PER_SEG, Pack::First), Err(CpError::Checksum));
}

#[test]
fn a_pack_longer_than_a_segment_is_rejected() {
    let head = cp_block(5, BLKS_PER_SEG + 1);
    assert_eq!(validate(&head, &head, BLKS_PER_SEG, Pack::First), Err(CpError::PackLength));
}

#[test]
fn a_pack_of_two_blocks_or_fewer_is_rejected() {
    for n in [0, 1, 2] {
        let head = cp_block(5, n);
        assert_eq!(validate(&head, &head, BLKS_PER_SEG, Pack::First), Err(CpError::PackLength));
    }
}

#[test]
fn a_pack_of_exactly_a_segment_is_accepted() {
    let head = cp_block(5, BLKS_PER_SEG);
    assert!(validate(&head, &head, BLKS_PER_SEG, Pack::First).is_ok());
}

#[test]
fn a_short_block_is_rejected() {
    assert_eq!(validate(&[0u8; 16], &[0u8; 16], BLKS_PER_SEG, Pack::First),
               Err(CpError::Truncated));
}

#[test]
fn the_pack_is_recorded_on_the_result() {
    let head = cp_block(5, 8);
    assert_eq!(validate(&head, &head, BLKS_PER_SEG, Pack::Second).unwrap().pack, Pack::Second);
}

#[test]
fn newer_compares_as_a_signed_difference() {
    assert!(newer(9, 8));
    assert!(!newer(8, 9));
    assert!(!newer(8, 8));
}

#[test]
fn newer_survives_the_counters_wrap() {
    // After the counter wraps the newer pack holds the SMALLER number; a plain
    // greater-than would mount a checkpoint older than the volume.
    assert!(newer(0, u64::MAX));
    assert!(!newer(u64::MAX, 0));
}

/// A parsed checkpoint with the given version and pack.
fn parsed(version: u64, pack: Pack) -> Checkpoint {
    let mut c = parse(&cp_block(version, 8), pack).unwrap();
    c.pack = pack;
    c
}

#[test]
fn choose_takes_the_newer_of_two_valid_packs() {
    let a = parsed(4, Pack::First);
    let b = parsed(7, Pack::Second);
    // Newer wins from either position; the argument order is which pack it
    // came from, not which is preferred.
    assert_eq!(choose(Some(a.clone()), Some(b.clone())).unwrap().version, 7);
    assert_eq!(choose(Some(a), Some(b)).unwrap().pack, Pack::Second);
}

#[test]
fn choose_prefers_the_first_pack_when_the_versions_tie() {
    let a = parsed(7, Pack::First);
    let b = parsed(7, Pack::Second);
    assert_eq!(choose(Some(a), Some(b)).unwrap().pack, Pack::First);
}

#[test]
fn choose_takes_the_only_valid_pack() {
    let a = parsed(1, Pack::First);
    let b = parsed(2, Pack::Second);
    assert_eq!(choose(Some(a), None).unwrap().pack, Pack::First);
    assert_eq!(choose(None, Some(b)).unwrap().pack, Pack::Second);
}

#[test]
fn choose_refuses_when_neither_pack_is_valid() {
    assert!(choose(None, None).is_none());
}

#[test]
fn the_second_packs_start_is_one_segment_on() {
    let a = parsed(1, Pack::First);
    let b = parsed(1, Pack::Second);
    assert_eq!(a.start(100, BLKS_PER_SEG), 100);
    assert_eq!(b.start(100, BLKS_PER_SEG), 100 + BLKS_PER_SEG);
}

#[test]
fn node_summaries_are_present_after_a_clean_unmount() {
    let mut c = parsed(1, Pack::First);
    c.flags = CP_UMOUNT_FLAG;
    assert!(c.node_summaries_present());
    c.flags = CP_FASTBOOT_FLAG;
    assert!(c.node_summaries_present());
    c.flags = 0;
    assert!(!c.node_summaries_present());
}

#[test]
fn has_reads_one_flag() {
    let mut c = parsed(1, Pack::First);
    c.flags = CP_ORPHAN_PRESENT_FLAG | CP_TRIMMED_FLAG;
    assert!(c.has(CP_ORPHAN_PRESENT_FLAG));
    assert!(c.has(CP_TRIMMED_FLAG));
    assert!(!c.has(CP_ERROR_FLAG));
}

#[test]
fn every_header_field_reads_back() {
    let mut c = vec![0u8; BLKSIZE];
    put64(&mut c, CP_CHECKPOINT_VER, 0x1122_3344_5566_7788);
    put64(&mut c, CP_USER_BLOCK_COUNT, 1000);
    put64(&mut c, CP_VALID_BLOCK_COUNT, 900);
    put32(&mut c, CP_RSVD_SEGMENT_COUNT, 3);
    put32(&mut c, CP_OVERPROV_SEGMENT_COUNT, 4);
    put32(&mut c, CP_FREE_SEGMENT_COUNT, 5);
    put32(&mut c, CP_CKPT_FLAGS, CP_UMOUNT_FLAG);
    put32(&mut c, CP_PACK_TOTAL_BLOCK_COUNT, 8);
    put32(&mut c, CP_PACK_START_SUM, 1);
    put32(&mut c, CP_VALID_NODE_COUNT, 6);
    put32(&mut c, CP_VALID_INODE_COUNT, 7);
    put32(&mut c, CP_NEXT_FREE_NID, 42);
    put32(&mut c, CP_SIT_VER_BITMAP_BYTESIZE, 64);
    put32(&mut c, CP_NAT_VER_BITMAP_BYTESIZE, 64);
    put32(&mut c, CP_CHECKSUM_OFFSET_FIELD, 4092);
    put64(&mut c, CP_ELAPSED_TIME, 99);
    let p = parse(&c, Pack::First).unwrap();
    assert_eq!(p.version, 0x1122_3344_5566_7788);
    assert_eq!((p.user_block_count, p.valid_block_count), (1000, 900));
    assert_eq!((p.rsvd_segment_count, p.overprov_segment_count, p.free_segment_count), (3, 4, 5));
    assert_eq!((p.pack_total_block_count, p.pack_start_sum), (8, 1));
    assert_eq!((p.valid_node_count, p.valid_inode_count, p.next_free_nid), (6, 7, 42));
    assert_eq!((p.sit_ver_bitmap_bytesize, p.nat_ver_bitmap_bytesize), (64, 64));
    assert_eq!((p.checksum_offset, p.elapsed_time), (4092, 99));
}

#[test]
fn the_current_segment_arrays_read_back_in_order() {
    let mut c = vec![0u8; BLKSIZE];
    for i in 0..MAX_ACTIVE_NODE_LOGS {
        put32(&mut c, CP_CUR_NODE_SEGNO + i * 4, 100 + i as u32);
        c[CP_CUR_NODE_BLKOFF + i * 2..CP_CUR_NODE_BLKOFF + i * 2 + 2]
            .copy_from_slice(&(10 + i as u16).to_le_bytes());
        put32(&mut c, CP_CUR_DATA_SEGNO + i * 4, 200 + i as u32);
        c[CP_CUR_DATA_BLKOFF + i * 2..CP_CUR_DATA_BLKOFF + i * 2 + 2]
            .copy_from_slice(&(20 + i as u16).to_le_bytes());
        c[CP_ALLOC_TYPE + i] = i as u8;
    }
    let p = parse(&c, Pack::First).unwrap();
    assert_eq!(p.cur_node_segno[0], 100);
    assert_eq!(p.cur_node_segno[7], 107);
    assert_eq!(p.cur_node_blkoff[7], 17);
    assert_eq!(p.cur_data_segno[3], 203);
    assert_eq!(p.cur_data_blkoff[3], 23);
    assert_eq!(p.alloc_type[5], 5);
}

#[test]
fn a_short_block_does_not_parse() {
    assert_eq!(parse(&[0u8; 100], Pack::First), None);
}

#[test]
fn joined_puts_the_payload_after_the_head() {
    let head = vec![1u8; BLKSIZE];
    let payload = vec![vec![2u8; BLKSIZE], vec![3u8; BLKSIZE]];
    let j = joined(&head, &payload);
    assert_eq!(j.len(), BLKSIZE * 3);
    assert_eq!(j[0], 1);
    assert_eq!(j[BLKSIZE], 2);
    assert_eq!(j[BLKSIZE * 2], 3);
}
