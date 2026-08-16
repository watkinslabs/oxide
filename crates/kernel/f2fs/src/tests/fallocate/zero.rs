//! `ZERO_RANGE`: zeroes that cost blocks.

use super::*;
use crate::fallocate::{FALLOC_FL_KEEP_SIZE, FALLOC_FL_ZERO_RANGE};

const Z: u32 = FALLOC_FL_ZERO_RANGE;
const B: u64 = BLKSIZE as u64;

#[test]
fn a_zeroed_range_reads_as_zeroes_after_a_remount() {
    let (mut v, ino) = with_file(4);
    v.fallocate(ino, Z, B, 2 * B).expect("zero");
    let (_, got) = settled(v, ino);
    let mut want = pattern(4);
    want[BLKSIZE..3 * BLKSIZE].fill(0);
    assert_eq!(got, want);
}

#[test]
fn zeroing_keeps_the_blocks_rather_than_freeing_them() {
    // The whole difference from punching: a write into the range afterwards
    // cannot fail for want of space.
    let (mut v, ino) = with_file(4);
    let before = v.read_inode(ino).expect("inode").blocks;
    v.fallocate(ino, Z, B, 2 * B).expect("zero");
    assert_eq!(v.read_inode(ino).expect("inode").blocks, before);
}

#[test]
fn zeroing_a_hole_gives_it_blocks() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"sparse", &spec(), None).expect("create");
    v.write_file(ino, 8 * B, b"tail").expect("write past a gap");
    let before = v.read_inode(ino).expect("inode").blocks;
    v.fallocate(ino, Z, 0, 4 * B).expect("zero the gap");
    let after = v.read_inode(ino).expect("inode").blocks;
    assert_eq!(after, before + 4, "the hole now costs four blocks");
}

#[test]
fn zeroing_past_the_end_grows_the_file() {
    let (mut v, ino) = with_file(2);
    v.fallocate(ino, Z, 2 * B, 2 * B).expect("zero");
    assert_eq!(v.read_inode(ino).expect("inode").size, 4 * B);
    let (_, got) = settled(v, ino);
    let mut want = pattern(2);
    want.extend(vec![0u8; 2 * BLKSIZE]);
    assert_eq!(got, want);
}

#[test]
fn keep_size_gives_the_blocks_and_leaves_the_length_alone() {
    let (mut v, ino) = with_file(2);
    let size = v.read_inode(ino).expect("inode").size;
    let before = v.read_inode(ino).expect("inode").blocks;
    v.fallocate(ino, Z | FALLOC_FL_KEEP_SIZE, 2 * B, 2 * B).expect("zero");
    let inode = v.read_inode(ino).expect("inode");
    assert_eq!(inode.size, size, "the length did not move");
    assert_eq!(inode.blocks, before + 2, "and the blocks are there");
}

#[test]
fn a_range_inside_one_block_zeroes_only_those_bytes() {
    let (mut v, ino) = with_file(2);
    v.fallocate(ino, Z, 10, 20).expect("zero");
    let (_, got) = settled(v, ino);
    let mut want = pattern(2);
    want[10..30].fill(0);
    assert_eq!(got, want);
}

#[test]
fn the_ragged_ends_are_zeroed_and_the_whole_blocks_replaced() {
    let (mut v, ino) = with_file(4);
    let off = B / 2;
    let len = 3 * B;
    v.fallocate(ino, Z, off, len).expect("zero");
    let (_, got) = settled(v, ino);
    let mut want = pattern(4);
    want[off as usize..(off + len) as usize].fill(0);
    assert_eq!(got, want);
}

#[test]
fn zeroing_a_file_living_inside_its_inode_moves_it_out() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"small", &spec(), None).expect("create");
    v.write_file(ino, 0, b"abcdefghij").expect("write");
    v.fallocate(ino, Z, 2, 4).expect("zero");
    assert!(!v.read_inode(ino).expect("inode").inline_data());
    let (_, got) = settled(v, ino);
    assert_eq!(&got, b"ab\0\0\0\0ghij");
}
