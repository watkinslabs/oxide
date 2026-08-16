//! Which block of a directory a hash lands in.

use super::*;
use crate::uapi::{MAX_DIR_BUCKETS, MAX_DIR_HASH_DEPTH};

#[test]
fn the_level_widths_double_until_they_stop() {
    assert_eq!(dir_buckets(0, 0), 1);
    assert_eq!(dir_buckets(1, 0), 2);
    assert_eq!(dir_buckets(2, 0), 4);
    assert_eq!(dir_buckets(30, 0), 1 << 30);
}

#[test]
fn the_widths_cap_at_the_formats_maximum() {
    // Level 31 and above take the cap; without it the shift would overflow.
    assert_eq!(dir_buckets(31, 0), MAX_DIR_BUCKETS);
    assert_eq!(dir_buckets(62, 0), MAX_DIR_BUCKETS);
    assert_eq!(MAX_DIR_BUCKETS, 1 << 30);
}

#[test]
fn the_cap_applies_at_exactly_half_the_maximum_depth() {
    let half = MAX_DIR_HASH_DEPTH / 2;
    assert_eq!(dir_buckets(half - 1, 0), 1 << (half - 1));
    assert_eq!(dir_buckets(half, 0), MAX_DIR_BUCKETS);
}

#[test]
fn the_directorys_own_level_shifts_every_width() {
    // Ignoring it puts every name in the wrong bucket of the right level.
    assert_eq!(dir_buckets(0, 2), 4);
    assert_eq!(dir_buckets(1, 2), 8);
    assert_ne!(dir_buckets(0, 2), dir_buckets(0, 0));
}

#[test]
fn the_directorys_own_level_also_moves_the_cap() {
    let half = MAX_DIR_HASH_DEPTH / 2;
    assert_eq!(dir_buckets(half - 2, 2), MAX_DIR_BUCKETS);
}

#[test]
fn a_bucket_holds_two_blocks_until_the_deep_levels() {
    assert_eq!(bucket_blocks(0), 2);
    assert_eq!(bucket_blocks(30), 2);
    assert_eq!(bucket_blocks(31), 4);
    assert_eq!(bucket_blocks(62), 4);
}

#[test]
fn level_zero_starts_at_block_zero() {
    assert_eq!(dir_block_index(0, 0, 0), 0);
}

#[test]
fn a_levels_first_block_counts_every_shallower_levels_blocks() {
    // Level 0 holds one bucket of two blocks; level 1 therefore starts at 2.
    assert_eq!(dir_block_index(1, 0, 0), 2);
    // Level 1 holds two buckets of two blocks; level 2 starts at 6.
    assert_eq!(dir_block_index(2, 0, 0), 6);
    assert_eq!(dir_block_index(3, 0, 0), 14);
}

#[test]
fn buckets_within_a_level_step_by_the_buckets_block_count() {
    assert_eq!(dir_block_index(1, 0, 1), 4);
    assert_eq!(dir_block_index(2, 0, 3), 6 + 6);
}

#[test]
fn a_directory_level_shifts_every_block_index() {
    assert_ne!(dir_block_index(1, 0, 0), dir_block_index(1, 2, 0));
    // With a base level of two, level zero already holds four buckets.
    assert_eq!(dir_block_index(1, 2, 0), 8);
}

#[test]
fn a_hash_falls_in_the_bucket_its_remainder_names() {
    assert_eq!(bucket_of(5, 1, 0), 1);
    assert_eq!(bucket_of(4, 1, 0), 0);
    assert_eq!(bucket_of(7, 2, 0), 3);
}

#[test]
fn every_hash_falls_in_the_only_bucket_of_level_zero() {
    for h in [0u32, 1, 0xFFFF_FFFF] { assert_eq!(bucket_of(h, 0, 0), 0); }
}

#[test]
fn a_search_range_covers_its_buckets_whole_block_span() {
    let r = search_range(0, 0, 0);
    assert_eq!(r, 0..2);
    let r = search_range(1, 1, 0);
    assert_eq!(r, 4..6);
}

#[test]
fn a_deep_levels_search_range_covers_four_blocks() {
    let r = search_range(0, 31, 0);
    assert_eq!(r.end - r.start, 4);
}

#[test]
fn two_hashes_in_different_buckets_search_different_blocks() {
    let a = search_range(0, 1, 0);
    let b = search_range(1, 1, 0);
    assert!(a.end <= b.start || b.end <= a.start);
}

#[test]
fn the_search_ranges_of_one_level_tile_it_without_gaps() {
    let level = 2u32;
    let n = dir_buckets(level, 0);
    let mut next = dir_block_index(level, 0, 0);
    for idx in 0..n {
        let r = search_range(idx, level, 0);
        assert_eq!(r.start, next);
        next = r.end;
    }
    assert_eq!(next, dir_block_index(level + 1, 0, 0));
}
