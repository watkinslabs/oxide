//! The footer marks and the offset arithmetic, with no medium in sight.

use super::*;
use crate::node::footer::{self, Footer};
use crate::node::path;
use alloc::vec;

fn f(flag: u32, cp_ver: u64) -> Footer {
    Footer { nid: 9, ino: 9, flag, cp_ver, next_blkaddr: 0 }
}

const APB: usize = 900;

#[test]
fn the_three_marks_occupy_three_different_bits() {
    assert_ne!(crate::flags::COLD_BIT_SHIFT, crate::flags::FSYNC_BIT_SHIFT);
    assert_ne!(crate::flags::FSYNC_BIT_SHIFT, crate::flags::DENT_BIT_SHIFT);
    assert!(crate::flags::COLD_BIT_SHIFT < crate::flags::OFFSET_BIT_SHIFT);
    assert!(crate::flags::FSYNC_BIT_SHIFT < crate::flags::OFFSET_BIT_SHIFT);
    assert!(crate::flags::DENT_BIT_SHIFT < crate::flags::OFFSET_BIT_SHIFT);
}

#[test]
fn a_flag_word_carries_its_offset_back_out() {
    for ofs in [0u32, 1, 2, 3, 17, 4096, 1_000_000] {
        assert_eq!(f(flag_word(ofs, false, false, false), 0).ofs_of_node(), ofs);
    }
}

#[test]
fn each_mark_is_independent_of_the_offset() {
    let w = flag_word(42, true, true, true);
    assert_eq!(f(w, 0).ofs_of_node(), 42);
    assert!(f(w, 0).is_fsync());
    assert!(f(w, 0).is_dent());
    assert!(f(w, 0).is_cold());
}

#[test]
fn a_word_without_marks_reports_none_of_them() {
    let w = flag_word(42, false, false, false);
    assert!(!f(w, 0).is_fsync());
    assert!(!f(w, 0).is_dent());
    assert!(!f(w, 0).is_cold());
}

#[test]
fn the_fsync_mark_is_not_the_dentry_mark() {
    assert!(f(flag_word(0, true, false, false), 0).is_fsync());
    assert!(!f(flag_word(0, true, false, false), 0).is_dent());
    assert!(f(flag_word(0, false, true, false), 0).is_dent());
    assert!(!f(flag_word(0, false, true, false), 0).is_fsync());
}

#[test]
fn the_cold_mark_is_not_the_fsync_mark() {
    assert!(f(flag_word(0, false, false, true), 0).is_cold());
    assert!(!f(flag_word(0, false, false, true), 0).is_fsync());
}

#[test]
fn a_node_of_this_generation_is_recoverable() {
    assert!(is_recoverable(&f(0, 7), 7, false));
}

#[test]
fn a_node_of_an_older_generation_is_not() {
    assert!(!is_recoverable(&f(0, 6), 7, false));
    assert!(!is_recoverable(&f(0, 8), 7, false));
}

#[test]
fn the_version_test_looks_at_the_whole_word() {
    let stamped = 7u64 | (0xDEAD_BEEFu64 << 32);
    assert!(!is_recoverable(&f(0, stamped), 7, false));
}

#[test]
fn the_no_checksum_form_ignores_the_upper_half() {
    let stamped = 7u64 | (0xDEAD_BEEFu64 << 32);
    assert!(is_recoverable(&f(0, stamped), 7, true));
}

#[test]
fn the_no_checksum_form_still_compares_the_version() {
    let stamped = 6u64 | (0xDEAD_BEEFu64 << 32);
    assert!(!is_recoverable(&f(0, stamped), 7, true));
}

#[test]
fn the_inode_and_the_two_direct_nodes_hold_addresses() {
    for ofs in [0u32, 1, 2] { assert!(is_dnode(ofs)); }
}

#[test]
fn the_indirect_nodes_do_not_hold_addresses() {
    let n = NIDS_PER_BLOCK as u32;
    assert!(!is_dnode(3));
    assert!(!is_dnode(4 + n));
    assert!(!is_dnode(5 + 2 * n));
}

#[test]
fn a_direct_node_under_an_indirect_one_holds_addresses() {
    let n = NIDS_PER_BLOCK as u32;
    assert!(is_dnode(4));
    assert!(is_dnode(5));
    assert!(is_dnode(3 + n));
    assert!(is_dnode(5 + n));
}

#[test]
fn the_indirect_nodes_under_the_double_indirect_one_do_not() {
    let n = NIDS_PER_BLOCK as u32;
    let base = 6 + 2 * n;
    assert!(!is_dnode(base));
    assert!(!is_dnode(base + (n + 1)));
    assert!(is_dnode(base + 1));
    assert!(is_dnode(base + n));
}

#[test]
fn the_attribute_node_offset_holds_addresses() {
    assert!(is_dnode(xattr_node_offset()));
}

#[test]
fn the_attribute_node_offset_is_outside_the_ordinary_range() {
    assert_eq!(xattr_node_offset(), u32::MAX >> crate::flags::OFFSET_BIT_SHIFT);
    assert!(xattr_node_offset() > 6 + 2 * NIDS_PER_BLOCK as u32);
}

#[test]
fn the_inode_covers_the_files_first_blocks() {
    assert_eq!(start_bidx_of_node(0, APB), 0);
}

#[test]
fn the_first_direct_node_starts_where_the_inode_stops() {
    assert_eq!(start_bidx_of_node(1, APB), APB as u64);
}

#[test]
fn the_second_direct_node_follows_the_first() {
    assert_eq!(start_bidx_of_node(2, APB), (APB + DEF_ADDRS_PER_BLOCK) as u64);
}

#[test]
fn an_indirect_nodes_number_is_not_counted_as_a_direct_one() {
    // Offset 4 is the first direct node UNDER the first indirect node, so it
    // must start exactly where offset 2 stopped.
    assert_eq!(start_bidx_of_node(4, APB), start_bidx_of_node(2, APB) + DEF_ADDRS_PER_BLOCK as u64);
}

#[test]
fn every_offset_the_path_walker_produces_maps_back_to_its_index() {
    let d = DEF_ADDRS_PER_BLOCK as u64;
    let p = NIDS_PER_BLOCK as u64;
    let probes = [
        0u64, 1, (APB as u64) - 1, APB as u64, APB as u64 + 1,
        APB as u64 + d - 1, APB as u64 + d, APB as u64 + 2 * d,
        APB as u64 + 2 * d + 1, APB as u64 + 2 * d + d, APB as u64 + 2 * d + d * p,
        APB as u64 + 2 * d + 2 * d * p, APB as u64 + 2 * d + 2 * d * p + d + 1,
    ];
    for idx in probes {
        let np = path::node_path(APB, idx).expect("addressable");
        let level = np.level as usize;
        let ofs = np.noffset[level] as u32;
        assert!(is_dnode(ofs), "offset {ofs} should hold addresses");
        assert_eq!(
            start_bidx_of_node(ofs, APB) + np.offset[level] as u64,
            idx,
            "offset {ofs} slot {} should reach index {idx}", np.offset[level]
        );
    }
}

#[test]
fn an_inodes_page_is_narrower_than_a_direct_nodes() {
    assert_eq!(addrs_per_page(true, APB), APB);
    assert_eq!(addrs_per_page(false, APB), DEF_ADDRS_PER_BLOCK);
}

#[test]
fn a_flag_written_into_a_block_parses_back_out() {
    let mut b = vec![0u8; BLKSIZE];
    let w = flag_word(11, true, false, true);
    set_flag(&mut b, w);
    let parsed = footer::parse(&b).expect("footer");
    assert_eq!(parsed.flag, w);
    assert_eq!(parsed.ofs_of_node(), 11);
    assert!(parsed.is_fsync());
}

#[test]
fn a_forward_pointer_written_into_a_block_parses_back_out() {
    let mut b = vec![0u8; BLKSIZE];
    set_next_blkaddr(&mut b, 0x1234_5678);
    assert_eq!(footer::parse(&b).expect("footer").next_blkaddr, 0x1234_5678);
}

#[test]
fn the_flag_and_the_forward_pointer_do_not_overlap() {
    let mut b = vec![0u8; BLKSIZE];
    set_flag(&mut b, flag_word(5, true, true, true));
    set_next_blkaddr(&mut b, 99);
    let p = footer::parse(&b).expect("footer");
    assert_eq!(p.next_blkaddr, 99);
    assert_eq!(p.ofs_of_node(), 5);
    assert!(p.is_fsync() && p.is_dent() && p.is_cold());
}
