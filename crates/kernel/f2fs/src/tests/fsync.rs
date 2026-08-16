//! `fsync` against a live volume: which path each state takes, and the shape
//! of the blocks the fast path leaves behind for the next mount to find.

use super::*;
use crate::mode::S_IFREG;
use crate::node::footer;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::*;
use crate::volume::curseg::Kind;
use crate::volume::recover::marks;
use crate::volume::{NewInode, Volume};
use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;

const NOW: (u64, u32) = (1_800_000_000, 7);
const BODY: usize = 2 * BLKSIZE;

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

fn body() -> Vec<u8> { (0..BODY).map(|i| i as u8).collect() }

/// A volume whose one file is fully checkpointed, which is the state in which
/// the fast path is available.
fn ready(opts: Options) -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_opts(opts).expect("mount");
    let ino = v.create(ROOT_INO, b"f", &spec(), None).expect("create");
    v.write_file(ino, 0, &body()).expect("write");
    v.commit().expect("commit");
    (v, ino)
}

fn log_pos(v: &Volume<MemImage>) -> (u32, u16) {
    let c = &v.logs()[CURSEG_WARM_NODE];
    (c.segno, c.next_blkoff)
}

/// The addresses the file-node log handed out between two positions.
fn emitted(v: &Volume<MemImage>, before: (u32, u16), after: (u32, u16)) -> Vec<u32> {
    assert_eq!(before.0, after.0, "fixture must not need a second segment");
    let base = v.super_block().main_blkaddr + before.0 * BLKS_PER_SEG;
    (before.1..after.1).map(|o| base + u32::from(o)).collect()
}

// -------------------------------------------------------------- which path

#[test]
fn a_checkpointed_regular_file_takes_the_chain() {
    let (mut v, ino) = ready(Options::defaults());
    assert_eq!(v.fsync(ino).expect("fsync"), CpReason::None);
}

#[test]
fn a_directory_takes_the_checkpoint() {
    let (mut v, _) = ready(Options::defaults());
    assert_eq!(v.fsync(ROOT_INO).expect("fsync"), CpReason::NonRegular);
}

#[test]
fn a_file_whose_parent_is_not_yet_durable_takes_the_checkpoint() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"new", &spec(), None).expect("create");
    assert_eq!(v.fsync(ino).expect("fsync"), CpReason::ParentNotCheckpointed);
}

#[test]
fn two_logs_take_the_checkpoint() {
    let opts = Options { active_logs: 2, ..Options::defaults() };
    let (mut v, ino) = ready(opts);
    assert_eq!(v.fsync(ino).expect("fsync"), CpReason::SpecLogNum);
}

#[test]
fn a_second_name_takes_the_checkpoint() {
    let (mut v, ino) = ready(Options::defaults());
    v.link(ROOT_INO, b"g", ino, NOW).expect("link");
    v.commit().expect("commit");
    assert_eq!(v.fsync(ino).expect("fsync"), CpReason::Hardlink);
}

#[test]
fn a_mount_that_cannot_write_reports_success_without_writing() {
    let v = test_image::with_root().mount_rw().expect("mount");
    let bytes = v.into_source().snapshot();
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes);
    let mut v = Volume::mount_with(img, Options::defaults(), false).expect("mount");
    let before = v.checkpoint().version;
    assert_eq!(v.fsync(ROOT_INO).expect("fsync"), CpReason::None);
    assert_eq!(v.checkpoint().version, before);
}

// ------------------------------------------------------- what each path costs

#[test]
fn the_chain_path_writes_no_checkpoint() {
    let (mut v, ino) = ready(Options::defaults());
    let before = v.checkpoint().version;
    v.write_file(ino, 0, b"x").expect("write");
    v.fsync(ino).expect("fsync");
    assert_eq!(v.checkpoint().version, before, "a chain must not cost a pack");
    assert!(v.is_dirty(), "the tables are still only in memory");
}

#[test]
fn the_checkpoint_path_writes_one() {
    let (mut v, ino) = ready(Options::defaults());
    let before = v.checkpoint().version;
    v.write_file(ino, 0, b"x").expect("write");
    assert!(v.fsync(ROOT_INO).expect("fsync").needed());
    assert_eq!(v.checkpoint().version, before + 1);
    assert!(!v.is_dirty());
}

// ------------------------------------------------------- the blocks it leaves

#[test]
fn the_chain_path_writes_one_block_per_node_of_the_file() {
    let (mut v, ino) = ready(Options::defaults());
    let inode = v.read_inode(ino).expect("inode");
    let expect = v.fsync_dnodes(ino, &inode).expect("nodes").len();
    let before = log_pos(&v);
    v.fsync(ino).expect("fsync");
    let got = emitted(&v, before, log_pos(&v));
    assert_eq!(got.len(), expect);
    assert!(!got.is_empty());
}

#[test]
fn a_small_file_has_only_its_inode_in_the_chain() {
    let (v, ino) = ready(Options::defaults());
    let inode = v.read_inode(ino).expect("inode");
    let list = v.fsync_dnodes(ino, &inode).expect("nodes");
    assert_eq!(list, alloc::vec![(ino, 0u32)]);
}

#[test]
fn every_block_the_chain_path_writes_carries_the_fsync_mark() {
    let (mut v, ino) = ready(Options::defaults());
    let before = log_pos(&v);
    v.fsync(ino).expect("fsync");
    for addr in emitted(&v, before, log_pos(&v)) {
        let f = footer::parse(&v.read_block(addr).expect("block")).expect("footer");
        assert!(f.is_fsync(), "block {addr} must be marked");
        assert!(f.is_cold(), "a file's node belongs to the file-node log");
        assert_eq!(f.cp_ver, v.checkpoint().version);
    }
}

#[test]
fn the_inode_leads_the_chain() {
    let (mut v, ino) = ready(Options::defaults());
    let before = log_pos(&v);
    v.fsync(ino).expect("fsync");
    let got = emitted(&v, before, log_pos(&v));
    let f = footer::parse(&v.read_block(got[0]).expect("block")).expect("footer");
    assert!(f.is_inode());
    assert_eq!(f.nid, ino);
    assert_eq!(f.ofs_of_node(), 0);
}

#[test]
fn each_link_names_the_block_that_follows_it() {
    let (mut v, ino) = ready(Options::defaults());
    let before = log_pos(&v);
    v.fsync(ino).expect("first");
    v.fsync(ino).expect("second");
    let got = emitted(&v, before, log_pos(&v));
    assert!(got.len() >= 2);
    for pair in got.windows(2) {
        let f = footer::parse(&v.read_block(pair[0]).expect("block")).expect("footer");
        assert_eq!(f.next_blkaddr, pair[1]);
        assert_ne!(f.next_blkaddr, pair[0], "a self-pointer stops the walk");
    }
}

#[test]
fn the_last_link_names_where_the_log_will_write_next() {
    let (mut v, ino) = ready(Options::defaults());
    let before = log_pos(&v);
    v.fsync(ino).expect("fsync");
    let got = emitted(&v, before, log_pos(&v));
    let last = *got.last().expect("at least one");
    let f = footer::parse(&v.read_block(last).expect("block")).expect("footer");
    assert_eq!(f.next_blkaddr, v.fsync_chain_start());
}

#[test]
fn a_checkpointed_inode_needs_no_dentry_mark() {
    let (mut v, ino) = ready(Options::defaults());
    let before = log_pos(&v);
    v.fsync(ino).expect("fsync");
    let got = emitted(&v, before, log_pos(&v));
    let f = footer::parse(&v.read_block(got[0]).expect("block")).expect("footer");
    assert!(!f.is_dent());
}

// ------------------------------------------------ the whole tree, not one node

/// Hang a node tree off `ino` by hand.
///
/// A file deep enough to need indirection is millions of blocks and cannot be
/// built in a fixture, but the enumeration does not care how many blocks the
/// nodes describe — only which slots name which nodes. Building the tree
/// directly exercises the walk at full depth for the cost of six blocks.
fn hang(v: &mut Volume<MemImage>, ino: u32, slot: usize, children: &[usize]) -> (u32, Vec<u32>) {
    let parent = v.alloc_nid().expect("nid");
    let mut block = vec![0u8; BLKSIZE];
    let mut kids = Vec::new();
    for &i in children {
        let nid = v.alloc_nid().expect("nid");
        v.write_node(nid, ino, vec![0u8; BLKSIZE], Kind::FileNode).expect("child");
        block[i * 4..i * 4 + 4].copy_from_slice(&nid.to_le_bytes());
        kids.push(nid);
    }
    v.write_node(parent, ino, block, Kind::IndirectNode).expect("parent");
    let mut inode = v.inode_bytes(ino).expect("bytes");
    let at = I_NID_OFF + slot * 4;
    inode[at..at + 4].copy_from_slice(&parent.to_le_bytes());
    v.put_inode(ino, inode).expect("inode");
    (parent, kids)
}

/// The tree offset of the first node under the first indirect slot.
const FIRST_UNDER_IND1: u32 = 4;

#[test]
fn the_two_direct_slots_come_back_with_the_offsets_the_tree_gives_them() {
    let (mut v, ino) = ready(Options::defaults());
    let d1 = v.alloc_nid().expect("nid");
    let d2 = v.alloc_nid().expect("nid");
    for nid in [d1, d2] {
        v.write_node(nid, ino, vec![0u8; BLKSIZE], Kind::FileNode).expect("direct");
    }
    let mut inode = v.inode_bytes(ino).expect("bytes");
    inode[I_NID_OFF..I_NID_OFF + 4].copy_from_slice(&d1.to_le_bytes());
    inode[I_NID_OFF + 4..I_NID_OFF + 8].copy_from_slice(&d2.to_le_bytes());
    v.put_inode(ino, inode).expect("inode");
    let read = v.read_inode(ino).expect("inode");
    assert_eq!(v.fsync_dnodes(ino, &read).expect("nodes"), vec![(ino, 0), (d1, 1), (d2, 2)]);
}

#[test]
fn the_direct_nodes_under_an_indirect_one_come_back_in_slot_order() {
    let (mut v, ino) = ready(Options::defaults());
    let (_, kids) = hang(&mut v, ino, 2, &[0, 1, 5]);
    let read = v.read_inode(ino).expect("inode");
    let got = v.fsync_dnodes(ino, &read).expect("nodes");
    assert_eq!(got[0], (ino, 0));
    assert_eq!(got[1], (kids[0], FIRST_UNDER_IND1));
    assert_eq!(got[2], (kids[1], FIRST_UNDER_IND1 + 1));
    assert_eq!(got[3], (kids[2], FIRST_UNDER_IND1 + 5));
    assert_eq!(got.len(), 4, "the indirect node itself holds no addresses");
}

#[test]
fn the_second_indirect_slot_starts_a_range_of_its_own() {
    let (mut v, ino) = ready(Options::defaults());
    let (_, kids) = hang(&mut v, ino, 3, &[0]);
    let read = v.read_inode(ino).expect("inode");
    let got = v.fsync_dnodes(ino, &read).expect("nodes");
    let base = 4 + NIDS_PER_BLOCK as u32;
    assert_eq!(got, vec![(ino, 0), (kids[0], base + 1)]);
}

#[test]
fn the_double_indirect_slot_is_walked_to_its_leaves() {
    let (mut v, ino) = ready(Options::defaults());
    // The middle level first, then the outer node pointing at it.
    let (mid, kids) = hang(&mut v, ino, 4, &[]);
    let leaf = v.alloc_nid().expect("nid");
    v.write_node(leaf, ino, vec![0u8; BLKSIZE], Kind::FileNode).expect("leaf");
    let inner = v.alloc_nid().expect("nid");
    let mut inner_block = vec![0u8; BLKSIZE];
    inner_block[..4].copy_from_slice(&leaf.to_le_bytes());
    v.write_node(inner, ino, inner_block, Kind::IndirectNode).expect("inner");
    let mut outer = v.read_node(mid, Some(ino)).expect("outer").block;
    outer[..4].copy_from_slice(&inner.to_le_bytes());
    v.write_node(mid, ino, outer, Kind::IndirectNode).expect("outer");
    assert!(kids.is_empty());
    let read = v.read_inode(ino).expect("inode");
    let got = v.fsync_dnodes(ino, &read).expect("nodes");
    let nids = NIDS_PER_BLOCK as u32;
    // Outer at 5+2N, its first inner at 6+2N, that inner's first leaf one past.
    assert_eq!(got, vec![(ino, 0), (leaf, 5 + 2 * nids + 2)]);
}

#[test]
fn every_offset_the_enumeration_reports_holds_addresses() {
    let (mut v, ino) = ready(Options::defaults());
    hang(&mut v, ino, 2, &[0, 3]);
    hang(&mut v, ino, 3, &[1]);
    let read = v.read_inode(ino).expect("inode");
    for (nid, ofs) in v.fsync_dnodes(ino, &read).expect("nodes") {
        assert!(marks::is_dnode(ofs), "node {nid} at offset {ofs} is an indirection node");
    }
}

#[test]
fn an_empty_slot_contributes_nothing() {
    let (mut v, ino) = ready(Options::defaults());
    let (_, kids) = hang(&mut v, ino, 2, &[0, 2]);
    let read = v.read_inode(ino).expect("inode");
    let got = v.fsync_dnodes(ino, &read).expect("nodes");
    assert_eq!(got.len(), 1 + kids.len(), "only the slots that name a node");
}

// ------------------------------------------------------------- the state read

#[test]
fn a_node_written_since_the_checkpoint_is_not_checkpointed() {
    let (mut v, ino) = ready(Options::defaults());
    assert!(v.node_is_checkpointed(ino));
    v.write_file(ino, 0, b"x").expect("write");
    assert!(!v.node_is_checkpointed(ino));
    v.commit().expect("commit");
    assert!(v.node_is_checkpointed(ino));
}

#[test]
fn the_gathered_state_matches_the_volume() {
    let (v, ino) = ready(Options::defaults());
    let s = v.sync_state(ino).expect("state");
    assert!(s.regular);
    assert!(!s.compressed);
    assert_eq!(s.links, 1);
    assert!(s.pino_ok);
    assert!(s.space_for_roll_forward);
    assert!(s.parent_checkpointed);
    assert_eq!(s.active_logs, Options::defaults().active_logs);
    assert!(!s.need_dentry_mark);
    assert_eq!(need_checkpoint(&s), CpReason::None);
}

#[test]
fn a_directorys_state_reports_it_is_not_regular() {
    let (v, _) = ready(Options::defaults());
    assert!(!v.sync_state(ROOT_INO).expect("state").regular);
}
