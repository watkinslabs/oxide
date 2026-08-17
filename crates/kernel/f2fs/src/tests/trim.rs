//! Freeing what a shortened or deleted file no longer needs.
//!
//! Every test here checks the SEGMENT TABLE as well as the reachability: a
//! block unhooked from a file but still marked live is the leak this module
//! exists to prevent, and it is invisible from the file's side.

use super::*;
use crate::mode::S_IFREG;
use crate::test_image::{self, ROOT_INO};
use crate::volume::{map::Mapped, NewInode, Volume};
use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;

const NOW: (u64, u32) = (1_800_000_000, 0);

fn with_file() -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let spec = NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW };
    let ino = v.create(ROOT_INO, b"f", &spec, None).unwrap();
    (v, ino)
}

/// The addresses of a file's allocated blocks at the given indices.
fn addrs(v: &Volume<MemImage>, ino: u32, indices: &[u64]) -> Vec<u32> {
    let inode = v.read_inode(ino).unwrap();
    indices
        .iter()
        .filter_map(|&i| match v.map_block(&inode, ino, i).unwrap() {
            Mapped::At(a) => Some(a),
            _ => None,
        })
        .collect()
}

#[test]
fn truncating_inside_the_inodes_own_array_releases_those_blocks() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![1u8; 4 * BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    let live = addrs(&v, ino, &[1, 2, 3]);
    assert_eq!(live.len(), 3);
    v.truncate_tail(ino, 1).unwrap();
    for a in live { assert!(!v.block_is_live(a).unwrap(), "block {a} leaked"); }
    assert_eq!(addrs(&v, ino, &[0]).len(), 1);
}

#[test]
fn truncating_to_nothing_releases_every_block() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![1u8; 3 * BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    let live = addrs(&v, ino, &[0, 1, 2]);
    v.truncate_tail(ino, 0).unwrap();
    for a in live { assert!(!v.block_is_live(a).unwrap()); }
}

#[test]
fn a_hole_costs_nothing_to_truncate_over() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    v.write_file(ino, 5 * BLKSIZE as u64, b"x").unwrap();
    v.sync_data().unwrap();
    let before = v.space().free;
    v.truncate_tail(ino, 6).unwrap();
    assert_eq!(v.space().free, before);
}

#[test]
fn a_direct_node_whose_range_is_gone_is_freed_with_its_blocks() {
    let (mut v, ino) = with_file();
    let apb = v.read_inode(ino).unwrap().addrs_per_inode() as u64;
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    v.write_file(ino, apb * BLKSIZE as u64, b"a").unwrap();
    v.sync_data().unwrap();
    v.write_file(ino, (apb + 3) * BLKSIZE as u64, b"b").unwrap();
    v.sync_data().unwrap();
    let nid = v.inode_slot(ino, 0).unwrap();
    assert_ne!(nid, 0);
    let node_block = v.node_addr(nid).unwrap();
    let data = addrs(&v, ino, &[apb, apb + 3]);
    assert_eq!(data.len(), 2);
    v.truncate_tail(ino, apb).unwrap();
    assert_eq!(v.inode_slot(ino, 0).unwrap(), 0);
    assert!(!v.block_is_live(node_block).unwrap(), "the node block leaked");
    for a in data { assert!(!v.block_is_live(a).unwrap(), "a data block leaked"); }
}

#[test]
fn a_direct_node_that_still_covers_a_block_keeps_its_slot() {
    let (mut v, ino) = with_file();
    let apb = v.read_inode(ino).unwrap().addrs_per_inode() as u64;
    v.write_file(ino, apb * BLKSIZE as u64, b"keep").unwrap();
    v.sync_data().unwrap();
    v.write_file(ino, (apb + 3) * BLKSIZE as u64, b"drop").unwrap();
    v.sync_data().unwrap();
    let keep = addrs(&v, ino, &[apb])[0];
    let drop = addrs(&v, ino, &[apb + 3])[0];
    v.truncate_tail(ino, apb + 1).unwrap();
    assert_ne!(v.inode_slot(ino, 0).unwrap(), 0);
    assert!(v.block_is_live(keep).unwrap());
    assert!(!v.block_is_live(drop).unwrap());
    assert_eq!(addrs(&v, ino, &[apb + 3]).len(), 0);
}

#[test]
fn an_indirect_node_whose_range_is_gone_is_freed_whole() {
    let (mut v, ino) = with_file();
    let apb = v.read_inode(ino).unwrap().addrs_per_inode() as u64;
    let base = apb + 2 * DEF_ADDRS_PER_BLOCK as u64;
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    v.write_file(ino, base * BLKSIZE as u64, b"deep").unwrap();
    v.sync_data().unwrap();
    let ind = v.inode_slot(ino, 2).unwrap();
    assert_ne!(ind, 0);
    let ind_block = v.node_addr(ind).unwrap();
    let data = addrs(&v, ino, &[base])[0];
    v.truncate_tail(ino, base).unwrap();
    assert_eq!(v.inode_slot(ino, 2).unwrap(), 0);
    assert!(!v.block_is_live(ind_block).unwrap(), "the indirect node leaked");
    assert!(!v.block_is_live(data).unwrap(), "the data block leaked");
}

#[test]
fn an_indirect_node_that_straddles_the_cut_keeps_its_surviving_child() {
    let (mut v, ino) = with_file();
    let apb = v.read_inode(ino).unwrap().addrs_per_inode() as u64;
    let d = DEF_ADDRS_PER_BLOCK as u64;
    let base = apb + 2 * d;
    v.write_file(ino, base * BLKSIZE as u64, b"keep").unwrap();
    v.sync_data().unwrap();
    v.write_file(ino, (base + d) * BLKSIZE as u64, b"drop").unwrap();
    v.sync_data().unwrap();
    let keep = addrs(&v, ino, &[base])[0];
    let drop = addrs(&v, ino, &[base + d])[0];
    v.truncate_tail(ino, base + 1).unwrap();
    assert_ne!(v.inode_slot(ino, 2).unwrap(), 0);
    assert!(v.block_is_live(keep).unwrap());
    assert!(!v.block_is_live(drop).unwrap());
}

#[test]
fn a_double_indirect_node_whose_range_is_gone_is_freed_whole() {
    let (mut v, ino) = with_file();
    let apb = v.read_inode(ino).unwrap().addrs_per_inode() as u64;
    let d = DEF_ADDRS_PER_BLOCK as u64;
    let p = NIDS_PER_BLOCK as u64;
    let base = apb + 2 * d + 2 * d * p;
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    v.write_file(ino, base * BLKSIZE as u64, b"dind").unwrap();
    v.sync_data().unwrap();
    let outer = v.inode_slot(ino, 4).unwrap();
    assert_ne!(outer, 0);
    let outer_block = v.node_addr(outer).unwrap();
    let data = addrs(&v, ino, &[base])[0];
    v.truncate_tail(ino, base).unwrap();
    assert_eq!(v.inode_slot(ino, 4).unwrap(), 0);
    assert!(!v.block_is_live(outer_block).unwrap());
    assert!(!v.block_is_live(data).unwrap());
}

#[test]
fn freeing_an_inode_releases_everything_it_owns() {
    let (mut v, ino) = with_file();
    let apb = v.read_inode(ino).unwrap().addrs_per_inode() as u64;
    v.write_file(ino, 0, &vec![1u8; 2 * BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    v.write_file(ino, apb * BLKSIZE as u64, b"far").unwrap();
    v.sync_data().unwrap();
    let inode_block = v.node_addr(ino).unwrap();
    let node = v.inode_slot(ino, 0).unwrap();
    let node_block = v.node_addr(node).unwrap();
    let data = addrs(&v, ino, &[0, 1, apb]);
    assert_eq!(data.len(), 3);
    v.free_inode(ino).unwrap();
    assert!(!v.block_is_live(inode_block).unwrap());
    assert!(!v.block_is_live(node_block).unwrap());
    for a in data { assert!(!v.block_is_live(a).unwrap()); }
}

#[test]
fn freeing_an_inode_gives_its_node_id_back() {
    let (mut v, ino) = with_file();
    v.free_inode(ino).unwrap();
    assert_eq!(v.node_addr(ino).unwrap(), NULL_ADDR);
    // The id comes back to the cache rather than being lost for the life of
    // the volume — but it is NOT the next one handed out. A released id joins
    // the TAIL of the free order, behind everything the cache already holds,
    // because something may still be naming an id that has just been released
    // and it is the last one that should be reused. So the claim to check is
    // that it is recorded free again and that the volume's remaining count
    // came back with it, not that the next file gets it.
    assert!(v.nid_is_cached_free(ino), "the freed id {ino} was not recorded free again");
    assert!(v.free_nid_counts().2 > 0);
    let spec = NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW };
    let next = v.create(ROOT_INO, b"g", &spec, None).unwrap();
    assert_ne!(next, ino, "an id released a moment ago was handed straight back out");
}

#[test]
fn the_block_count_a_truncation_leaves_matches_the_tree() {
    let (mut v, ino) = with_file();
    let apb = v.read_inode(ino).unwrap().addrs_per_inode() as u64;
    v.write_file(ino, 0, &vec![1u8; 2 * BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    v.write_file(ino, apb * BLKSIZE as u64, b"far").unwrap();
    v.sync_data().unwrap();
    // Inode + two data + one direct node + one data under it.
    assert_eq!(v.count_blocks(ino).unwrap(), 5);
    v.truncate_file(ino, BLKSIZE as u64).unwrap();
    assert_eq!(v.count_blocks(ino).unwrap(), 2);
    assert_eq!(v.read_inode(ino).unwrap().blocks, 2);
}

#[test]
fn counting_a_sparse_file_does_not_walk_its_length() {
    // A file whose length spans the double-indirect range holds three blocks;
    // counting by index would do millions of lookups to find them.
    let (mut v, ino) = with_file();
    let apb = v.read_inode(ino).unwrap().addrs_per_inode() as u64;
    let d = DEF_ADDRS_PER_BLOCK as u64;
    let p = NIDS_PER_BLOCK as u64;
    let far = apb + 2 * d + 2 * d * p;
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    v.write_file(ino, far * BLKSIZE as u64, b"end").unwrap();
    v.sync_data().unwrap();
    assert!(v.read_inode(ino).unwrap().size > 1_000_000_000);
    // Inode, one data block, the three-deep node chain, and the far block.
    assert_eq!(v.count_blocks(ino).unwrap(), 6);
}

#[test]
fn an_inline_file_counts_as_its_one_block() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, b"tiny").unwrap();
    v.sync_data().unwrap();
    assert!(v.read_inode(ino).unwrap().inline_data());
    assert_eq!(v.count_blocks(ino).unwrap(), 1);
}
