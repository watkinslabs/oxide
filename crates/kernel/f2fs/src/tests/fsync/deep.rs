//! A file deep enough that its addresses live under indirection, driven the
//! whole way: written through the ordinary path, promised by `fsync`, lost to
//! a crash, and read back after the replay.
//!
//! The enumeration is tested elsewhere against a tree hung by hand, which
//! proves the walk visits the slots it is given. It cannot prove the walk
//! visits the slots the WRITER produces, and those are the only ones a caller
//! ever has: a real file reaches indirection only at index nine hundred and
//! something, so a fixture that builds two blocks and stops has never once
//! exercised the path a large file takes.
//!
//! The files here are sparse. One block written at a high index allocates the
//! indirection nodes above it and nothing else, so a file whose LENGTH is
//! eight gigabytes costs five blocks to build and the whole depth is reached
//! in a hosted test.

use super::*;

use crate::volume::fsync::CpReason;
use crate::volume::recover::fixture::*;
use crate::volume::recover::marks;
use crate::volume::{map::Mapped, Volume};
use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;

/// The first file index reached through the FIRST indirect node.
fn under_indirect(apb: u64) -> u64 { apb + 2 * DEF_ADDRS_PER_BLOCK as u64 }

/// The first file index reached through the double-indirect node.
fn under_double_indirect(apb: u64) -> u64 {
    let d = DEF_ADDRS_PER_BLOCK as u64;
    let p = NIDS_PER_BLOCK as u64;
    apb + 2 * d + 2 * d * p
}

fn addrs_per_inode(v: &Volume<MemImage>, ino: u32) -> u64 {
    v.read_inode(ino).expect("inode").addrs_per_inode() as u64
}

/// Put one block at `index` through the writer a caller uses.
fn write_at(v: &mut Volume<MemImage>, ino: u32, index: u64, byte: u8) -> Vec<u8> {
    let body = vec![byte; BLKSIZE];
    v.write_file(ino, index * BLKSIZE as u64, &body).expect("write");
    body
}

fn block_at(v: &Volume<MemImage>, ino: u32, index: u64) -> Vec<u8> {
    let inode = v.read_inode(ino).expect("inode");
    let mut out = vec![0u8; BLKSIZE];
    let got = v.read_file(&inode, ino, index * BLKSIZE as u64, &mut out).expect("read");
    assert_eq!(got, BLKSIZE, "the whole block came back");
    out
}

/// The chain's own view: which node covers `index`, taken from the walk.
fn covering(v: &Volume<MemImage>, ino: u32, index: u64) -> (u32, u32) {
    let inode = v.read_inode(ino).expect("inode");
    let apb = inode.addrs_per_inode();
    let list = v.fsync_dnodes(ino, &inode).expect("nodes");
    *list
        .iter()
        .find(|&&(_, ofs)| {
            let start = marks::start_bidx_of_node(ofs, apb);
            index >= start && index < start + marks::addrs_per_page(ofs == 0, apb) as u64
        })
        .expect("a node covering the index")
}

#[test]
fn a_block_under_an_indirect_node_is_enumerated_by_the_walk() {
    let (mut v, ino, _) = checkpointed(b"f");
    let index = under_indirect(addrs_per_inode(&v, ino));
    write_at(&mut v, ino, index, 0xE1);
    let (nid, ofs) = covering(&v, ino, index);
    assert_ne!(nid, ino, "the address is not in the inode's own array");
    assert!(marks::is_dnode(ofs), "an indirection node holds no addresses");
    assert_eq!(marks::start_bidx_of_node(ofs, addrs_per_inode(&v, ino) as usize), index);
}

#[test]
fn a_block_under_an_indirect_node_survives_a_crash() {
    let (mut v, ino, _) = checkpointed(b"f");
    let index = under_indirect(addrs_per_inode(&v, ino));
    let want = write_at(&mut v, ino, index, 0xE1);
    assert_eq!(v.fsync(ino).expect("fsync"), CpReason::None, "the chain path, not a pack");
    let v = crash(v);
    assert_eq!(block_at(&v, ino, index), want);
}

#[test]
fn a_block_under_the_double_indirect_node_survives_a_crash() {
    let (mut v, ino, _) = checkpointed(b"f");
    let index = under_double_indirect(addrs_per_inode(&v, ino));
    let want = write_at(&mut v, ino, index, 0xD2);
    let (nid, ofs) = covering(&v, ino, index);
    assert_ne!(nid, ino);
    assert!(marks::is_dnode(ofs));
    assert_eq!(v.fsync(ino).expect("fsync"), CpReason::None);
    let v = crash(v);
    assert_eq!(block_at(&v, ino, index), want);
    assert_eq!(v.read_inode(ino).expect("inode").size, (index + 1) * BLKSIZE as u64);
}

#[test]
fn every_depth_of_one_file_comes_back_together() {
    // The inode's own array, a direct node, an indirect node and the
    // double-indirect node in one file and one promise. A walk that stops at
    // the first level it does not understand loses the deeper ones silently.
    let (mut v, ino, _) = checkpointed(b"f");
    let apb = addrs_per_inode(&v, ino);
    let shallow = 1u64;
    let direct = apb;
    let indirect = under_indirect(apb);
    let deep = under_double_indirect(apb);
    let mut want = Vec::new();
    for (i, &index) in [shallow, direct, indirect, deep].iter().enumerate() {
        want.push((index, write_at(&mut v, ino, index, 0xA0 + i as u8)));
    }
    assert_eq!(v.fsync(ino).expect("fsync"), CpReason::None);
    let v = crash(v);
    for (index, body) in want {
        assert_eq!(block_at(&v, ino, index), body, "index {index}");
    }
}

#[test]
fn the_chain_carries_one_marked_block_for_each_node_the_walk_names() {
    let (mut v, ino, _) = checkpointed(b"f");
    let apb = addrs_per_inode(&v, ino);
    write_at(&mut v, ino, under_indirect(apb), 0xE1);
    write_at(&mut v, ino, under_double_indirect(apb), 0xD2);
    let inode = v.read_inode(ino).expect("inode");
    let expect = v.fsync_dnodes(ino, &inode).expect("nodes");
    assert!(expect.len() >= 3, "the inode and two nodes under indirection");
    let start = v.fsync_chain_start();
    v.fsync(ino).expect("fsync");
    let mut marked = Vec::new();
    v.walk_chain(start, &mut |f| { marked.push((f.nid, f.ofs)); true }).expect("walk");
    assert_eq!(marked, expect, "the chain holds exactly what the walk named");
}

#[test]
fn the_indirection_nodes_themselves_are_not_in_the_chain() {
    // They carry node ids, not addresses, and replay rebuilds them from the
    // addresses it recovers. Writing them would add links that say nothing —
    // and, worse, offer replay a node id the checkpoint's table cannot resolve.
    let (mut v, ino, _) = checkpointed(b"f");
    let apb = addrs_per_inode(&v, ino);
    write_at(&mut v, ino, under_double_indirect(apb), 0xD2);
    let start = v.fsync_chain_start();
    v.fsync(ino).expect("fsync");
    v.walk_chain(start, &mut |f| {
        assert!(marks::is_dnode(f.ofs), "node {} at offset {} holds no addresses", f.nid, f.ofs);
        true
    })
    .expect("walk");
}

#[test]
fn a_deep_block_is_live_and_pointed_at_after_the_replay() {
    let (mut v, ino, _) = checkpointed(b"f");
    let index = under_double_indirect(addrs_per_inode(&v, ino));
    write_at(&mut v, ino, index, 0xD2);
    v.fsync(ino).expect("fsync");
    let mut v = crash(v);
    let inode = v.read_inode(ino).expect("inode");
    let Mapped::At(addr) = v.map_block(&inode, ino, index).expect("map") else {
        panic!("the deep block")
    };
    v.load_segments().expect("segments");
    assert!(v.addr_is_live(addr), "a recovered block the allocator must not hand out");
    assert_eq!(v.read_block(addr).expect("block"), vec![0xD2u8; BLKSIZE], "the bytes written");
}

#[test]
fn a_deep_block_nothing_promised_does_not_survive() {
    // The paired negative: the same write without the promise is gone, so the
    // recovery above is the chain's doing and not something the ordinary write
    // path already made durable.
    let (mut v, ino, _) = checkpointed(b"f");
    let index = under_double_indirect(addrs_per_inode(&v, ino));
    write_at(&mut v, ino, index, 0xD2);
    let v = crash(v);
    let inode = v.read_inode(ino).expect("inode");
    assert!(inode.size < index * BLKSIZE as u64, "the file is as the checkpoint left it");
}
