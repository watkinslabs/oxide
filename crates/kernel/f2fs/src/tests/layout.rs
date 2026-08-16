//! The four regions of a dentry area.
//!
//! Both shapes are pinned to NUMBERS, not to the expressions that produce
//! them: an inline area reserves seven bytes of padding where a block reserves
//! three, and a build that used the block's number for both would put every
//! inline record four bytes early.

use super::*;

#[test]
fn a_blocks_region_sizes_are_what_the_format_defines() {
    let l = Layout::block();
    assert_eq!(l.max, 214);
    assert_eq!(l.bitmap_len, 27);
    assert_eq!(SIZE_OF_RESERVED, 3);
    assert_eq!(l.dentry_at, 30);
    assert_eq!(l.filename_at, 30 + 11 * 214);
    assert_eq!(l.len, BLKSIZE);
}

#[test]
fn a_blocks_four_regions_fill_it_exactly() {
    let l = Layout::block();
    assert_eq!(l.filename_at + l.max * SLOT_LEN, BLKSIZE);
    assert!(l.fits());
}

#[test]
fn the_default_inline_area_sizes_are_what_the_format_defines() {
    // The area an inode with no extra attributes and the fixed reservation
    // has left: 923 - 50 - 1 slots, four bytes each.
    let l = Layout::inline(3488);
    assert_eq!(l.max, 182);
    assert_eq!(l.bitmap_len, 23);
    assert_eq!(l.dentry_at, 23 + 7);
    assert_eq!(l.filename_at, 30 + 11 * 182);
    assert!(l.fits());
}

#[test]
fn an_inline_area_reserves_more_padding_than_a_block() {
    let inline = Layout::inline(3488);
    let block = Layout::block();
    let inline_pad = inline.dentry_at - inline.bitmap_len;
    let block_pad = block.dentry_at - block.bitmap_len;
    assert_eq!(inline_pad, 7);
    assert_eq!(block_pad, 3);
    assert_ne!(inline_pad, block_pad);
}

#[test]
fn an_inline_areas_four_regions_fill_it_exactly() {
    for bytes in [40usize, 400, 1024, 3452, 3488] {
        let l = Layout::inline(bytes);
        assert_eq!(l.filename_at + l.max * SLOT_LEN, bytes, "at {bytes} bytes");
        assert!(l.fits(), "at {bytes} bytes");
    }
}

#[test]
fn the_narrowest_area_the_format_defines_holds_two_entries() {
    let l = Layout::inline(40);
    assert_eq!(l.max, 2);
    assert_eq!(l.bitmap_len, 1);
}

#[test]
fn an_area_too_small_for_one_entry_does_not_fit() {
    assert!(!Layout::inline(8).fits());
}

#[test]
fn the_area_of_an_inode_with_extra_attributes_is_smaller() {
    // 923 - 9 - 50 - 1 slots.
    let l = Layout::inline(3452);
    assert_eq!(l.max, 180);
    assert_ne!(l.max, Layout::inline(3488).max);
}

#[test]
fn record_offsets_step_by_the_record_size() {
    let l = Layout::block();
    assert_eq!(l.dentry_off(0), 30);
    assert_eq!(l.dentry_off(1), 41);
    assert_eq!(l.dentry_off(213), 30 + 213 * 11);
}

#[test]
fn name_slot_offsets_step_by_the_slot_size() {
    let l = Layout::block();
    assert_eq!(l.name_off(0), l.filename_at);
    assert_eq!(l.name_off(1), l.filename_at + 8);
    assert_eq!(l.name_off(213) + 8, BLKSIZE);
}

#[test]
fn the_last_record_stops_before_the_first_name_slot() {
    let l = Layout::block();
    assert_eq!(l.dentry_off(l.max - 1) + SIZE_OF_DIR_ENTRY, l.filename_at);
}

#[test]
fn the_bitmap_counts_from_the_low_bit_of_byte_zero() {
    let area = [0b0000_0110u8, 0b0000_0001];
    assert!(!is_used(&area, 0));
    assert!(is_used(&area, 1));
    assert!(is_used(&area, 2));
    assert!(is_used(&area, 8));
    assert!(!is_used(&area, 9));
}

#[test]
fn a_bit_past_the_area_reads_as_free() {
    assert!(!is_used(&[0xFFu8], 8));
    assert!(!is_used(&[], 0));
}

#[test]
fn the_bitmap_is_wide_enough_for_every_entry() {
    for l in [Layout::block(), Layout::inline(3488), Layout::inline(40)] {
        assert!(l.bitmap_len * 8 >= l.max);
        assert!((l.bitmap_len - 1) * 8 < l.max);
    }
}
