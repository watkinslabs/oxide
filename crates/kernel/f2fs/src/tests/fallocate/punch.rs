//! `PUNCH_HOLE`, proved by remounting the image bytes.

use super::*;
use crate::fallocate::FALLOC_FL_PUNCH_HOLE;

const P: u32 = FALLOC_FL_PUNCH_HOLE;
const B: u64 = BLKSIZE as u64;

#[test]
fn a_whole_block_punched_out_reads_as_zeroes_after_a_remount() {
    let (mut v, ino) = with_file(4);
    v.fallocate(ino, P, B, B).expect("punch");
    let (_, got) = settled(v, ino);
    let want = { let mut w = pattern(4); w[BLKSIZE..2 * BLKSIZE].fill(0); w };
    assert_eq!(got, want);
}

#[test]
fn a_punch_frees_the_blocks_it_covers() {
    let (mut v, ino) = with_file(4);
    let before = v.read_inode(ino).expect("inode").blocks;
    v.fallocate(ino, P, B, 2 * B).expect("punch");
    let after = v.read_inode(ino).expect("inode").blocks;
    assert_eq!(after, before - 2, "two whole blocks came back");
}

#[test]
fn the_length_never_changes() {
    let (mut v, ino) = with_file(4);
    let size = v.read_inode(ino).expect("inode").size;
    v.fallocate(ino, P, 0, 2 * B).expect("punch");
    assert_eq!(v.read_inode(ino).expect("inode").size, size);
    // Including a punch that reaches the last byte: that is what parts this
    // from shortening.
    v.fallocate(ino, P, 3 * B, B).expect("punch the tail");
    assert_eq!(v.read_inode(ino).expect("inode").size, size);
}

#[test]
fn a_partial_block_is_zeroed_in_place_and_keeps_its_other_half() {
    let (mut v, ino) = with_file(2);
    // Bytes 100..200 of block zero only.
    v.fallocate(ino, P, 100, 100).expect("punch");
    let (_, got) = settled(v, ino);
    let mut want = pattern(2);
    want[100..200].fill(0);
    assert_eq!(got, want);
}

#[test]
fn the_ragged_ends_of_a_multi_block_punch_are_zeroed_and_the_middle_freed() {
    let (mut v, ino) = with_file(4);
    let before = v.read_inode(ino).expect("inode").blocks;
    // From half way through block zero to half way through block three.
    let off = B / 2;
    let len = 3 * B;
    v.fallocate(ino, P, off, len).expect("punch");
    let after = v.read_inode(ino).expect("inode").blocks;
    assert_eq!(after, before - 2, "blocks one and two were whole and went");
    let (_, got) = settled(v, ino);
    let mut want = pattern(4);
    want[off as usize..(off + len) as usize].fill(0);
    assert_eq!(got, want);
}

#[test]
fn punching_a_hole_that_is_already_a_hole_costs_nothing_and_changes_nothing() {
    let (mut v, ino) = with_file(4);
    v.fallocate(ino, P, B, 2 * B).expect("punch");
    let blocks = v.read_inode(ino).expect("inode").blocks;
    v.fallocate(ino, P, B, 2 * B).expect("punch again");
    assert_eq!(v.read_inode(ino).expect("inode").blocks, blocks);
    let (_, got) = settled(v, ino);
    let mut want = pattern(4);
    want[BLKSIZE..3 * BLKSIZE].fill(0);
    assert_eq!(got, want);
}

#[test]
fn a_punch_past_the_end_is_accepted_and_does_nothing() {
    let (mut v, ino) = with_file(2);
    let before = v.read_inode(ino).expect("inode").blocks;
    v.fallocate(ino, P, 10 * B, B).expect("punch");
    assert_eq!(v.read_inode(ino).expect("inode").blocks, before);
}

#[test]
fn a_file_living_inside_its_inode_moves_out_before_it_is_punched() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"small", &spec(), None).expect("create");
    v.write_file(ino, 0, b"abcdefghij").expect("write");
    assert!(v.read_inode(ino).expect("inode").inline_data());
    v.fallocate(ino, P, 2, 4).expect("punch");
    assert!(!v.read_inode(ino).expect("inode").inline_data(), "it left the inode");
    let (_, got) = settled(v, ino);
    assert_eq!(&got, b"ab\0\0\0\0ghij");
}

#[test]
fn the_volumes_own_count_says_the_space_came_back() {
    // The count the checkpoint carries, not the inode's. Clearing the slots
    // alone makes the FILE report fewer blocks while the volume still counts
    // them as occupied — a block that no file names and nothing will ever
    // reclaim. Only the volume-wide count can tell the two apart.
    let (mut v, ino) = with_file(4);
    v.commit().expect("commit");
    let before = v.space().free;
    v.fallocate(ino, P, 0, 4 * B).expect("punch it all");
    v.commit().expect("commit");
    assert_eq!(v.space().free, before + 4, "four blocks came back to the volume");
}

#[test]
fn the_freed_run_is_reachable_through_a_remount() {
    // And the count survives the medium, so what came back was recorded
    // rather than only decremented in memory.
    let (mut v, ino) = with_file(4);
    v.commit().expect("commit");
    let before = v.space().free;
    v.fallocate(ino, P, 0, 4 * B).expect("punch it all");
    let (v, got) = settled(v, ino);
    assert_eq!(got, vec![0u8; 4 * BLKSIZE], "and reads as zeroes");
    assert_eq!(v.space().free, before + 4);
}

#[test]
fn punching_the_ragged_ends_leaks_nothing_either() {
    // The mixed path: two edges rewritten in place and a middle freed. Each
    // rewrite allocates a fresh block and releases the one it replaced, so a
    // release missed anywhere shows as a count that did not come back.
    let (mut v, ino) = with_file(4);
    v.commit().expect("commit");
    let before = v.space().free;
    v.fallocate(ino, P, B / 2, 3 * B).expect("punch");
    v.commit().expect("commit");
    assert_eq!(v.space().free, before + 2, "the two whole blocks, and no more");
}
