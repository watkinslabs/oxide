//! The inode's cached extent: consumed on read, kept true across writes.
//!
//! The extent is a CACHE, and the only thing that makes a cache safe is that
//! it can never disagree with the truth. Every test here checks the fast path
//! against the node walk that would have run without it.

use crate::mode::S_IFREG;
use crate::uapi::*;
use crate::opts::Options;
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

fn remount(mut v: Volume<MemImage>) -> Volume<MemImage> {
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

/// Every block index of a file, resolved with the cache and without it.
fn agree(v: &Volume<MemImage>, ino: u32) {
    let inode = v.read_inode(ino).unwrap();
    let blocks = inode.size.div_ceil(BLKSIZE as u64);
    for index in 0..blocks {
        let cached = inode.extent_addr(index);
        if cached.is_none() { continue; }
        // Resolve the same index with the cache emptied, which is the walk the
        // reader would have done.
        let mut bare = inode.clone();
        bare.ext = (0, 0, 0);
        let walked = v.map_block(&bare, ino, index).unwrap();
        assert_eq!(walked, crate::volume::map::Mapped::At(cached.unwrap()),
                   "index {index}: cache and walk disagree");
    }
}

#[test]
fn a_file_with_no_extent_reports_none() {
    let (v, ino) = with_file();
    assert_eq!(v.read_inode(ino).unwrap().cached_extent(), None);
}

#[test]
fn a_zero_length_extent_is_no_extent() {
    let (v, ino) = with_file();
    let mut inode = v.read_inode(ino).unwrap();
    inode.ext = (0, 5000, 0);
    assert_eq!(inode.cached_extent(), None);
    assert_eq!(inode.extent_addr(0), None);
}

#[test]
fn an_extent_answers_only_inside_its_own_range() {
    let (v, ino) = with_file();
    let mut inode = v.read_inode(ino).unwrap();
    inode.ext = (10, 5000, 3);
    assert_eq!(inode.extent_addr(9), None);
    assert_eq!(inode.extent_addr(10), Some(5000));
    assert_eq!(inode.extent_addr(12), Some(5002));
    assert_eq!(inode.extent_addr(13), None);
}

#[test]
fn an_extent_that_would_overflow_its_own_arithmetic_is_refused() {
    let (v, ino) = with_file();
    let mut inode = v.read_inode(ino).unwrap();
    inode.ext = (u32::MAX - 1, 5000, 8);
    assert_eq!(inode.cached_extent(), None);
    inode.ext = (0, u32::MAX, 8);
    assert_eq!(inode.cached_extent(), None);
}

#[test]
fn a_contiguous_write_records_an_extent() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![7u8; 4 * BLKSIZE]).unwrap();
    let (fofs, blk, len) = v.read_inode(ino).unwrap().cached_extent().unwrap();
    assert_eq!(fofs, 0);
    assert_eq!(len, 4);
    assert!(v.sb_main_contains(blk));
    agree(&v, ino);
}

#[test]
fn the_recorded_extent_survives_a_remount_and_still_agrees() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![7u8; 4 * BLKSIZE]).unwrap();
    let v = remount(v);
    assert!(v.read_inode(ino).unwrap().cached_extent().is_some());
    agree(&v, ino);
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(v.read_whole(&inode, ino).unwrap(), vec![7u8; 4 * BLKSIZE]);
}

#[test]
fn an_inline_file_records_no_extent() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, b"tiny").unwrap();
    assert!(v.read_inode(ino).unwrap().inline_data());
    assert_eq!(v.read_inode(ino).unwrap().cached_extent(), None);
}

#[test]
fn a_hole_at_the_start_records_no_extent() {
    // The run recorded begins at offset zero; a file that starts with a hole
    // has none to record, and inventing one would name a block it does not own.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.write_file(ino, 3 * BLKSIZE as u64, b"far").unwrap();
    v.truncate_file(ino, 0).unwrap();
    v.write_file(ino, 2 * BLKSIZE as u64, b"only far").unwrap();
    assert_eq!(v.read_inode(ino).unwrap().cached_extent(), None);
}

#[test]
fn a_run_broken_by_a_hole_stops_at_the_hole() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![1u8; 2 * BLKSIZE]).unwrap();
    v.write_file(ino, 5 * BLKSIZE as u64, b"beyond").unwrap();
    let (_, _, len) = v.read_inode(ino).unwrap().cached_extent().unwrap();
    assert_eq!(len, 2, "the run ran through a hole");
    agree(&v, ino);
}

#[test]
fn rewriting_a_block_keeps_the_extent_true() {
    // The rewritten block moves, so an extent left alone would point at a
    // block this file no longer owns.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![1u8; 4 * BLKSIZE]).unwrap();
    let before = v.read_inode(ino).unwrap().cached_extent().unwrap();
    v.write_file(ino, BLKSIZE as u64, &vec![2u8; BLKSIZE]).unwrap();
    let after = v.read_inode(ino).unwrap().cached_extent();
    assert_ne!(Some(before), after, "the extent still describes the old layout");
    agree(&v, ino);
    let inode = v.read_inode(ino).unwrap();
    let mut buf = [0u8; 1];
    v.read_file(&inode, ino, BLKSIZE as u64, &mut buf).unwrap();
    assert_eq!(buf[0], 2);
}

#[test]
fn truncating_keeps_the_extent_true() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![1u8; 6 * BLKSIZE]).unwrap();
    v.truncate_file(ino, 2 * BLKSIZE as u64).unwrap();
    agree(&v, ino);
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(v.read_whole(&inode, ino).unwrap().len(), 2 * BLKSIZE);
}

#[test]
fn truncating_to_nothing_forgets_the_extent() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![1u8; 4 * BLKSIZE]).unwrap();
    v.truncate_file(ino, 0).unwrap();
    assert_eq!(v.read_inode(ino).unwrap().cached_extent(), None);
}

#[test]
fn an_extent_outside_the_main_area_is_not_trusted() {
    // A stale or corrupt extent must fall through to the walk rather than
    // hand back a metadata block as file data.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![1u8; 2 * BLKSIZE]).unwrap();
    let mut inode = v.read_inode(ino).unwrap();
    inode.ext = (0, 1, 2);
    assert!(!v.extent_is_sane(&inode));
    // The walk still answers correctly despite the bad cache.
    assert!(matches!(v.map_block(&inode, ino, 0).unwrap(),
                     crate::volume::map::Mapped::At(_)));
}

#[test]
fn an_extent_whose_tail_leaves_the_main_area_is_not_trusted() {
    // Checking only the first block would accept a run that walks off the end.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    let mut inode = v.read_inode(ino).unwrap();
    let end = test_image::MAIN_BLKADDR + test_image::SEG_MAIN * BLKS_PER_SEG;
    inode.ext = (0, end - 2, 8);
    assert!(v.sb_main_contains(end - 2));
    assert!(!v.extent_is_sane(&inode));
}

#[test]
fn a_bad_extent_never_changes_what_a_read_returns() {
    let (mut v, ino) = with_file();
    let data: Vec<u8> = (0..3 * BLKSIZE).map(|i| (i % 251) as u8).collect();
    v.write_file(ino, 0, &data).unwrap();
    let mut inode = v.read_inode(ino).unwrap();
    inode.ext = (0, 1, 3);
    assert_eq!(v.read_whole(&inode, ino).unwrap(), data);
}

#[test]
fn the_cache_and_the_walk_agree_over_many_shapes() {
    for blocks in [1usize, 2, 3, 5, 8] {
        let (mut v, ino) = with_file();
        v.write_file(ino, 0, &vec![9u8; blocks * BLKSIZE]).unwrap();
        agree(&v, ino);
        let v = remount(v);
        agree(&v, ino);
    }
}

#[test]
fn a_block_written_under_the_cache_is_the_block_that_reads_back() {
    // The cache answers from the addresses the inode held when it was last
    // computed. An out-of-place write moves a block, so leaving the cache
    // alone makes every later read of that block return its PREVIOUS
    // contents — stale data, with no error anywhere to say so.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![7u8; 3 * BLKSIZE]).unwrap();
    let inode = v.read_inode(ino).unwrap();
    assert!(v.extent_is_sane(&inode), "no cache to invalidate; the test proves nothing");
    v.write_one_block(ino, 1, 0, &vec![8u8; BLKSIZE]).unwrap();
    let inode = v.read_inode(ino).unwrap();
    let mut buf = vec![0u8; BLKSIZE];
    v.read_file(&inode, ino, BLKSIZE as u64, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 8), "the read came from the block's old address");
    // And the walk agrees with the cache afterwards, at every index.
    agree(&v, ino);
}

#[test]
fn converting_an_inline_file_leaves_no_content_in_the_address_array() {
    // The inline region IS the address array. Content left behind in it is
    // read afterwards as a block address: a file of 0x01 bytes leaves
    // 0x01010101 in a slot, which either fails the read or, if it happens to
    // land inside the main area, hands back a block belonging to another file.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![1u8; 100]).unwrap();
    assert!(v.read_inode(ino).unwrap().inline_data(), "the fixture was never inline");
    v.convert_inline(ino).unwrap();
    let inode = v.read_inode(ino).unwrap();
    let block = v.inode_bytes(ino).unwrap();
    let base = inode.addr_base();
    for slot in 1..inode.addrs_per_inode() {
        let at = base + slot * 4;
        assert_eq!(crate::uapi::le32(&block, at), Some(0),
                   "slot {} still holds the file's own bytes", slot);
    }
    // The proof it matters: a write far into the file now lands instead of
    // tripping over a leftover byte pattern read as an address.
    v.write_one_block(ino, 16, 0, &vec![5u8; BLKSIZE]).unwrap();
    let inode = v.read_inode(ino).unwrap();
    assert!(matches!(v.map_block(&inode, ino, 16).unwrap(), Mapped::At(_)));
}
