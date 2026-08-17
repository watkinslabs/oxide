//! The node footer, and whether a block is the node that was asked for.

use super::*;
use crate::test_image::meta::{put32, put64};
use alloc::vec;
use alloc::vec::Vec;

/// A node block whose footer names `nid` and `ino`.
fn block(nid: u32, ino: u32, flag: u32) -> Vec<u8> {
    let mut b = vec![0u8; BLKSIZE];
    let f = NODE_FOOTER_OFF;
    put32(&mut b, f + FOOTER_NID, nid);
    put32(&mut b, f + FOOTER_INO, ino);
    put32(&mut b, f + FOOTER_FLAG, flag);
    put64(&mut b, f + FOOTER_CP_VER, 99);
    put32(&mut b, f + FOOTER_NEXT_BLKADDR, 1234);
    b
}

#[test]
fn the_footer_sits_in_the_blocks_last_twenty_four_bytes() {
    assert_eq!(NODE_FOOTER_SIZE, 24);
    assert_eq!(NODE_FOOTER_OFF, BLKSIZE - 24);
}

#[test]
fn every_footer_field_reads_back() {
    let f = parse(&block(7, 3, 0x18)).unwrap();
    assert_eq!(f.nid, 7);
    assert_eq!(f.ino, 3);
    assert_eq!(f.flag, 0x18);
    assert_eq!(f.cp_ver, 99);
    assert_eq!(f.next_blkaddr, 1234);
}

#[test]
fn a_node_whose_own_id_is_its_inode_number_is_an_inode() {
    assert!(parse(&block(3, 3, 0)).unwrap().is_inode());
    assert!(!parse(&block(7, 3, 0)).unwrap().is_inode());
}

#[test]
fn the_offset_within_the_tree_lives_above_the_mark_bits() {
    // The low three bits are marks; reading the whole word as an offset gives
    // a number eight times too large.
    let f = parse(&block(7, 3, 5 << 3)).unwrap();
    assert_eq!(f.ofs_of_node(), 5);
}

#[test]
fn the_directory_mark_is_its_own_bit() {
    assert!(parse(&block(7, 3, 1 << 2)).unwrap().is_dent());
    assert!(!parse(&block(7, 3, 1 << 1)).unwrap().is_dent());
}

#[test]
fn a_block_matching_its_node_id_is_accepted() {
    assert!(expect(&block(7, 3, 0), 7, Some(3)).is_ok());
}

#[test]
fn a_block_carrying_another_node_id_is_rejected() {
    // The table pointed somewhere stale; reading it anyway returns a node from
    // another file with no error.
    assert_eq!(expect(&block(8, 3, 0), 7, Some(3)),
               Err(NodeError::WrongNid { want: 7, got: 8 }));
}

#[test]
fn a_block_belonging_to_another_file_is_rejected() {
    assert_eq!(expect(&block(7, 4, 0), 7, Some(3)),
               Err(NodeError::WrongIno { want: 3, got: 4 }));
}

#[test]
fn the_inode_number_is_not_checked_when_the_caller_does_not_know_it() {
    // An inode's own read cannot check it: the footer is what states it.
    assert!(expect(&block(7, 4, 0), 7, None).is_ok());
}

#[test]
fn a_short_block_is_rejected_rather_than_read_past() {
    assert_eq!(expect(&[0u8; 100], 7, None), Err(NodeError::Truncated));
    assert_eq!(parse(&[0u8; 100]), None);
}

#[test]
fn an_address_out_of_a_direct_node_is_bounded_by_the_arrays_width() {
    let b = vec![0u8; BLKSIZE];
    assert!(crate::node::direct_addr(&b, DEF_ADDRS_PER_BLOCK - 1).is_some());
    assert!(crate::node::direct_addr(&b, DEF_ADDRS_PER_BLOCK).is_none());
}

#[test]
fn a_direct_nodes_last_address_stops_before_its_footer() {
    // Slot 1017 ends at byte 4072, which is exactly where the footer begins.
    assert_eq!((DEF_ADDRS_PER_BLOCK - 1) * 4 + 4, NODE_FOOTER_OFF);
}

#[test]
fn a_node_id_out_of_an_indirect_node_is_bounded_the_same_way() {
    let b = vec![0u8; BLKSIZE];
    assert!(crate::node::indirect_nid(&b, NIDS_PER_BLOCK - 1).is_some());
    assert!(crate::node::indirect_nid(&b, NIDS_PER_BLOCK).is_none());
}

#[test]
fn both_hole_spellings_read_as_holes() {
    assert!(crate::node::is_hole(NULL_ADDR));
    assert!(crate::node::is_hole(NEW_ADDR));
    assert!(!crate::node::is_hole(1));
    assert!(!crate::node::is_hole(COMPRESS_ADDR));
}

#[test]
fn the_compressed_marker_is_its_own_value() {
    assert!(crate::node::is_compressed(COMPRESS_ADDR));
    assert_eq!(COMPRESS_ADDR, u32::MAX - 1);
    assert!(!crate::node::is_compressed(NEW_ADDR));
}
