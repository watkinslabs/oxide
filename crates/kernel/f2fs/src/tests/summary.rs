//! The summary block's derived sizes, and decoding the two journals.

use super::*;
use crate::test_image::meta::{put16, put32, put64};
use alloc::vec;
use alloc::vec::Vec;

#[test]
fn the_derived_sizes_are_what_the_format_defines() {
    assert_eq!(ENTRIES_IN_SUM, 512);
    assert_eq!(SUM_JOURNAL_OFF, 3584);
    assert_eq!(SUM_JOURNAL_SIZE, 507);
    assert_eq!(NAT_JOURNAL_ENTRY_SIZE, 13);
    assert_eq!(SIT_JOURNAL_ENTRY_SIZE, 78);
    assert_eq!(NAT_JOURNAL_ENTRIES, 38);
    assert_eq!(SIT_JOURNAL_ENTRIES, 6);
}

#[test]
fn the_packed_summary_feature_changes_nothing_at_this_block_size() {
    // The feature makes the summary block a fixed four kibibytes instead of
    // the volume's block size. At a four-kibibyte block those are the same
    // number, so every derived offset is identical and a volume carrying the
    // bit is read correctly by the ordinary path. That is why the bit is
    // ACCEPTED rather than refused — it is conformance, not a gap.
    const PACKED_SUM_BLOCKSIZE: usize = 4096;
    assert_eq!(BLKSIZE, PACKED_SUM_BLOCKSIZE);
    let entries = |sum_blocksize: usize| sum_blocksize / 8;
    let journal_off = |sum_blocksize: usize| SUMMARY_SIZE * entries(sum_blocksize);
    let journal_size =
        |sb: usize| sb - SUM_FOOTER_SIZE - journal_off(sb);
    assert_eq!(entries(PACKED_SUM_BLOCKSIZE), ENTRIES_IN_SUM);
    assert_eq!(journal_off(PACKED_SUM_BLOCKSIZE), SUM_JOURNAL_OFF);
    assert_eq!(journal_size(PACKED_SUM_BLOCKSIZE), SUM_JOURNAL_SIZE);
    assert_eq!((journal_size(PACKED_SUM_BLOCKSIZE) - 2) / NAT_JOURNAL_ENTRY_SIZE,
               NAT_JOURNAL_ENTRIES);
}

#[test]
fn a_wider_block_would_change_every_derived_offset() {
    // The positive half of the claim above: at a block size this build does
    // not accept, the packed form and the ordinary form genuinely differ — so
    // the equality asserted above is a property of 4096, not of the formulas.
    const WIDE: usize = 16384;
    let entries = |sum_blocksize: usize| sum_blocksize / 8;
    assert_ne!(entries(WIDE), entries(4096));
    assert_ne!(SUMMARY_SIZE * entries(WIDE), SUM_JOURNAL_OFF);
}

#[test]
fn one_summary_block_covers_exactly_one_segment() {
    // The entry array is one slot per block of a segment; a mismatch would
    // leave the tail of a segment with no owner recorded.
    assert_eq!(ENTRIES_IN_SUM, BLKS_PER_SEG as usize);
}

#[test]
fn the_entries_journal_and_footer_fill_the_block_exactly() {
    assert_eq!(SUM_JOURNAL_OFF + SUM_JOURNAL_SIZE + SUM_FOOTER_SIZE, BLKSIZE);
}

#[test]
fn a_node_table_entry_reads_its_three_fields() {
    let mut b = vec![0u8; 64];
    b[10 + NAT_VERSION] = 3;
    put32(&mut b, 10 + NAT_INO, 77);
    put32(&mut b, 10 + NAT_BLOCK_ADDR, 4242);
    let e = nat_entry(&b, 10).unwrap();
    assert_eq!(e, NatEntry { version: 3, ino: 77, block_addr: 4242 });
}

#[test]
fn a_node_table_entry_past_the_buffer_is_reported() {
    assert_eq!(nat_entry(&[0u8; 4], 0), None);
}

#[test]
fn a_segment_table_entry_reads_its_count_map_and_time() {
    let mut b = vec![0u8; 256];
    put16(&mut b, SIT_VBLOCKS, (4 << SIT_VBLOCKS_SHIFT) | 9);
    b[SIT_VALID_MAP] = 0b0000_1001;
    put64(&mut b, SIT_MTIME, 12345);
    let e = sit_entry(&b, 0).unwrap();
    assert_eq!(e.valid_blocks(), 9);
    assert_eq!(e.seg_type(), 4);
    assert_eq!(e.mtime, 12345);
    assert!(e.is_valid(0));
    assert!(!e.is_valid(1));
    assert!(e.is_valid(3));
}

#[test]
fn a_segment_entrys_count_and_type_share_one_word() {
    // The count occupies the low ten bits and the type the rest; reading the
    // whole word as a count reports an impossible occupancy.
    let mut b = vec![0u8; 256];
    put16(&mut b, SIT_VBLOCKS, (5 << SIT_VBLOCKS_SHIFT) | 511);
    let e = sit_entry(&b, 0).unwrap();
    assert_eq!(e.valid_blocks(), 511);
    assert_eq!(e.seg_type(), 5);
}

#[test]
fn a_bit_past_the_segments_map_reads_as_clear() {
    let e = sit_entry(&vec![0xFFu8; 256], 0).unwrap();
    assert!(e.is_valid(SIT_VBLOCK_MAP_SIZE * 8 - 1));
    assert!(!e.is_valid(SIT_VBLOCK_MAP_SIZE * 8));
}

/// A block holding a node-table journal of `n` entries at `off`.
fn nat_journal_block(off: usize, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; BLKSIZE];
    put16(&mut b, off, n as u16);
    for i in 0..n {
        let at = off + 2 + i * NAT_JOURNAL_ENTRY_SIZE;
        put32(&mut b, at, 100 + i as u32);
        b[at + 4 + NAT_VERSION] = i as u8;
        put32(&mut b, at + 4 + NAT_INO, 200 + i as u32);
        put32(&mut b, at + 4 + NAT_BLOCK_ADDR, 300 + i as u32);
    }
    b
}

#[test]
fn a_node_journal_decodes_in_order() {
    let b = nat_journal_block(at::NORMAL, 3);
    let j = nat_journal(&b, at::NORMAL).unwrap();
    assert_eq!(j.len(), 3);
    assert_eq!(j[0].0, 100);
    assert_eq!(j[2].1.block_addr, 302);
}

#[test]
fn an_empty_node_journal_decodes_to_nothing() {
    let b = nat_journal_block(at::NORMAL, 0);
    assert!(nat_journal(&b, at::NORMAL).unwrap().is_empty());
}

#[test]
fn a_full_node_journal_decodes_every_entry() {
    let b = nat_journal_block(at::NORMAL, NAT_JOURNAL_ENTRIES);
    assert_eq!(nat_journal(&b, at::NORMAL).unwrap().len(), NAT_JOURNAL_ENTRIES);
}

#[test]
fn an_absurd_journal_count_is_clamped_rather_than_read_past() {
    let mut b = nat_journal_block(at::NORMAL, 4);
    put16(&mut b, at::NORMAL, 60000);
    assert_eq!(nat_journal(&b, at::NORMAL).unwrap().len(), NAT_JOURNAL_ENTRIES);
}

#[test]
fn the_last_journal_entry_stays_inside_the_journal_region() {
    let last = at::NORMAL + 2 + (NAT_JOURNAL_ENTRIES - 1) * NAT_JOURNAL_ENTRY_SIZE
        + NAT_JOURNAL_ENTRY_SIZE;
    assert!(last <= at::NORMAL + SUM_JOURNAL_SIZE);
}

#[test]
fn a_segment_journal_decodes_in_order() {
    let mut b = vec![0u8; BLKSIZE];
    put16(&mut b, at::NORMAL, 2);
    for i in 0..2usize {
        let at = at::NORMAL + 2 + i * SIT_JOURNAL_ENTRY_SIZE;
        put32(&mut b, at, 7 + i as u32);
        put16(&mut b, at + 4 + SIT_VBLOCKS, 11 + i as u16);
    }
    let j = sit_journal(&b, at::NORMAL).unwrap();
    assert_eq!(j.len(), 2);
    assert_eq!(j[1].0, 8);
    assert_eq!(j[1].1.valid_blocks(), 12);
}

#[test]
fn the_compact_layout_puts_the_two_journals_back_to_back() {
    assert_eq!(at::COMPACT_NAT, 0);
    assert_eq!(at::COMPACT_SIT, SUM_JOURNAL_SIZE);
    assert_ne!(at::COMPACT_NAT, at::NORMAL);
}

#[test]
fn a_compact_block_decodes_both_journals_from_one_block() {
    let mut b = nat_journal_block(at::COMPACT_NAT, 2);
    put16(&mut b, at::COMPACT_SIT, 1);
    put32(&mut b, at::COMPACT_SIT + 2, 5);
    assert_eq!(nat_journal(&b, at::COMPACT_NAT).unwrap().len(), 2);
    let sit = sit_journal(&b, at::COMPACT_SIT).unwrap();
    assert_eq!(sit.len(), 1);
    assert_eq!(sit[0].0, 5);
}

#[test]
fn the_summary_address_counts_back_from_the_packs_end() {
    // The six persistent logs' blocks are the last before the tail, in order.
    let start = 1000u32;
    let total = 8u32;
    assert_eq!(normal_sum_addr(start, total, 6, 0), 1001);
    assert_eq!(normal_sum_addr(start, total, 6, 2), 1003);
    assert_eq!(normal_sum_addr(start, total, 6, 5), 1006);
    // The tail block sits one past the last summary.
    assert_eq!(start + total - 1, 1007);
}

#[test]
fn a_pack_without_node_summaries_uses_the_shorter_base() {
    // With only the three data logs written, the same log sits three blocks
    // further on; using the wrong base reads a node summary as a data one.
    let start = 1000u32;
    assert_eq!(normal_sum_addr(start, 8, 3, 0), 1004);
    assert_ne!(normal_sum_addr(start, 8, 3, 0), normal_sum_addr(start, 8, 6, 0));
}
