//! The chain walk, against blocks laid down by hand so every stopping rule
//! can be provoked on its own.

use crate::test_image;
use crate::uapi::{BLKS_PER_SEG, BLKSIZE, CURSEG_WARM_NODE};
use crate::volume::recover::marks;
use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;
use syscall::errno::Errno;

/// The generation the fixture's checkpoint carries.
const GEN: u64 = 7;

/// Where a walk starts on the fixture: the file-node log's segment, which the
/// fixture leaves empty and positioned at its first block.
fn head() -> u32 { test_image::MAIN_BLKADDR + CURSEG_WARM_NODE as u32 * BLKS_PER_SEG }

fn node(nid: u32, ino: u32, flag: u32, cp_ver: u64, next: u32) -> Vec<u8> {
    let mut b = vec![0u8; BLKSIZE];
    let f = crate::uapi::NODE_FOOTER_OFF;
    b[f..f + 4].copy_from_slice(&nid.to_le_bytes());
    b[f + 4..f + 8].copy_from_slice(&ino.to_le_bytes());
    b[f + 12..f + 20].copy_from_slice(&cp_ver.to_le_bytes());
    marks::set_flag(&mut b, flag);
    marks::set_next_blkaddr(&mut b, next);
    b
}

/// A read-only volume with `blocks` laid at consecutive addresses from the
/// chain head.
fn with_chain(blocks: &[Vec<u8>]) -> crate::volume::Volume<MemImage> {
    // Laid down AFTER the mount, which is where a crash leaves a chain: a
    // mount is the thing that has to survive reading one, and an image built
    // with a malformed chain already in it cannot be mounted to look at.
    let mut v = test_image::with_root().mount_rw().expect("mount");
    for (i, blk) in blocks.iter().enumerate() {
        v.write_block(head() + i as u32, blk).expect("block");
    }
    v
}

fn fsync_node(nid: u32, next: u32) -> Vec<u8> {
    node(nid, nid, marks::flag_word(0, true, false, true), GEN, next)
}

#[test]
fn an_untouched_log_yields_no_chain() {
    let v = test_image::with_root().mount().expect("mount");
    assert_eq!(v.scan_fsync_chain().expect("scan"), Vec::new());
    assert!(!v.has_fsync_data().expect("probe"));
}

#[test]
fn the_walk_begins_at_the_file_node_logs_next_block() {
    let v = test_image::with_root().mount().expect("mount");
    assert_eq!(v.fsync_chain_start(), head());
}

#[test]
fn a_marked_node_of_this_generation_is_found() {
    let v = with_chain(&[fsync_node(40, head())]);
    let got = v.scan_fsync_chain().expect("scan");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].nid, 40);
    assert_eq!(got[0].addr, head());
    assert!(got[0].fsync);
    assert!(v.has_fsync_data().expect("probe"));
}

#[test]
fn a_node_without_the_mark_is_walked_through_but_not_returned() {
    let plain = node(41, 41, marks::flag_word(0, false, false, true), GEN, head() + 1);
    let v = with_chain(&[plain, fsync_node(42, head() + 1)]);
    let got = v.scan_fsync_chain().expect("scan");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].nid, 42);
}

#[test]
fn the_walk_stops_at_a_node_of_another_generation() {
    let stale = node(43, 43, marks::flag_word(0, true, false, true), GEN - 1, head() + 1);
    let v = with_chain(&[stale, fsync_node(44, head() + 1)]);
    assert_eq!(v.scan_fsync_chain().expect("scan"), Vec::new());
}

#[test]
fn a_node_after_a_stale_one_is_never_reached() {
    let first = fsync_node(45, head() + 1);
    let stale = node(46, 46, marks::flag_word(0, true, false, true), GEN + 1, head() + 2);
    let past = fsync_node(47, head() + 2);
    let v = with_chain(&[first, stale, past]);
    let got = v.scan_fsync_chain().expect("scan");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].nid, 45);
}

#[test]
fn the_walk_stops_when_the_pointer_leaves_the_main_area() {
    let v = with_chain(&[fsync_node(48, 0)]);
    let got = v.scan_fsync_chain().expect("scan");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].nid, 48);
}

#[test]
fn a_pointer_into_the_metadata_area_is_not_followed() {
    let v = with_chain(&[fsync_node(49, test_image::NAT_BLKADDR)]);
    assert_eq!(v.scan_fsync_chain().expect("scan").len(), 1);
}

#[test]
fn a_pointer_past_the_end_of_the_volume_is_not_followed() {
    let v = with_chain(&[fsync_node(50, u32::MAX - 1)]);
    assert_eq!(v.scan_fsync_chain().expect("scan").len(), 1);
}

#[test]
fn a_pointer_at_the_blocks_own_address_ends_the_chain() {
    let v = with_chain(&[fsync_node(51, head()), fsync_node(52, head() + 1)]);
    let got = v.scan_fsync_chain().expect("scan");
    assert_eq!(got.len(), 1, "a chain that cannot advance is one block long");
    assert_eq!(got[0].nid, 51);
}

#[test]
fn a_two_block_cycle_is_refused() {
    let a = fsync_node(53, head() + 1);
    let b = fsync_node(54, head());
    let v = with_chain(&[a, b]);
    assert_eq!(v.scan_fsync_chain().err(), Some(Errno::Einval));
}

#[test]
fn a_three_block_cycle_is_refused() {
    let a = fsync_node(55, head() + 1);
    let b = fsync_node(56, head() + 2);
    let c = fsync_node(57, head());
    let v = with_chain(&[a, b, c]);
    assert_eq!(v.scan_fsync_chain().err(), Some(Errno::Einval));
}

#[test]
fn a_cycle_that_does_not_include_the_head_is_refused() {
    let a = fsync_node(58, head() + 1);
    let b = fsync_node(59, head() + 2);
    let c = fsync_node(60, head() + 1);
    let v = with_chain(&[a, b, c]);
    assert_eq!(v.scan_fsync_chain().err(), Some(Errno::Einval));
}

#[test]
fn a_long_chain_that_terminates_is_not_mistaken_for_a_cycle() {
    let mut blocks = Vec::new();
    for i in 0..32u32 { blocks.push(fsync_node(70 + i, head() + i + 1)); }
    blocks.push(fsync_node(200, 0));
    let v = with_chain(&blocks);
    assert_eq!(v.scan_fsync_chain().expect("scan").len(), 33);
}

#[test]
fn the_chain_comes_back_in_the_order_the_log_wrote_it() {
    let mut blocks = Vec::new();
    for i in 0..5u32 { blocks.push(fsync_node(80 + i, head() + i + 1)); }
    let v = with_chain(&blocks);
    let got = v.scan_fsync_chain().expect("scan");
    let nids: Vec<u32> = got.iter().map(|f| f.nid).collect();
    assert_eq!(nids, alloc::vec![80, 81, 82, 83, 84]);
}

#[test]
fn the_dentry_mark_comes_back_with_the_node() {
    let marked = node(90, 90, marks::flag_word(0, true, true, true), GEN, head() + 1);
    let plain = node(91, 90, marks::flag_word(1, true, false, true), GEN, 0);
    let v = with_chain(&[marked, plain]);
    let got = v.scan_fsync_chain().expect("scan");
    assert!(got[0].dent);
    assert!(!got[1].dent);
}

#[test]
fn an_inode_block_is_told_apart_from_a_direct_node() {
    let inode = fsync_node(92, head() + 1);
    let direct = node(93, 92, marks::flag_word(1, true, false, true), GEN, 0);
    let v = with_chain(&[inode, direct]);
    let got = v.scan_fsync_chain().expect("scan");
    assert!(got[0].is_inode);
    assert_eq!(got[0].ofs, 0);
    assert!(!got[1].is_inode);
    assert_eq!(got[1].ofs, 1);
    assert_eq!(got[1].ino, 92);
}
