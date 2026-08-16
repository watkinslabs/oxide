//! The plain allocation, with and without `KEEP_SIZE`, pinned and not.

use super::*;
use crate::fallocate::FALLOC_FL_KEEP_SIZE;

const B: u64 = BLKSIZE as u64;

#[test]
fn allocating_past_the_end_grows_the_file_and_gives_it_blocks() {
    let (mut v, ino) = with_file(2);
    let before = v.read_inode(ino).expect("inode").blocks;
    v.fallocate(ino, 0, 2 * B, 2 * B).expect("allocate");
    let inode = v.read_inode(ino).expect("inode");
    assert_eq!(inode.size, 4 * B);
    assert_eq!(inode.blocks, before + 2);
}

#[test]
fn the_allocated_range_reads_as_zeroes_after_a_remount() {
    let (mut v, ino) = with_file(2);
    v.fallocate(ino, 0, 2 * B, 2 * B).expect("allocate");
    let (_, got) = settled(v, ino);
    let mut want = pattern(2);
    want.extend(vec![0u8; 2 * BLKSIZE]);
    assert_eq!(got, want);
}

#[test]
fn keep_size_gives_the_blocks_and_leaves_the_length_alone() {
    let (mut v, ino) = with_file(2);
    let before = v.read_inode(ino).expect("inode").blocks;
    v.fallocate(ino, FALLOC_FL_KEEP_SIZE, 2 * B, 2 * B).expect("allocate");
    let inode = v.read_inode(ino).expect("inode");
    assert_eq!(inode.size, 2 * B, "the length did not move");
    assert_eq!(inode.blocks, before + 2, "and the blocks are there");
}

#[test]
fn allocating_over_blocks_that_already_exist_changes_nothing() {
    let (mut v, ino) = with_file(4);
    let before = v.read_inode(ino).expect("inode").blocks;
    v.fallocate(ino, FALLOC_FL_KEEP_SIZE, 0, 4 * B).expect("allocate");
    assert_eq!(v.read_inode(ino).expect("inode").blocks, before);
    let (_, got) = settled(v, ino);
    assert_eq!(got, pattern(4), "the contents were not rewritten");
}

#[test]
fn allocating_a_hole_in_the_middle_fills_only_the_hole() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"sparse", &spec(), None).expect("create");
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).expect("block 0");
    v.write_file(ino, 4 * B, &vec![5u8; BLKSIZE]).expect("block 4");
    v.commit().expect("commit");
    let before = v.read_inode(ino).expect("inode").blocks;
    v.fallocate(ino, FALLOC_FL_KEEP_SIZE, 0, 5 * B).expect("allocate");
    assert_eq!(v.read_inode(ino).expect("inode").blocks, before + 3);
    let (_, got) = settled(v, ino);
    let mut want = vec![1u8; BLKSIZE];
    want.extend(vec![0u8; 3 * BLKSIZE]);
    want.extend(vec![5u8; BLKSIZE]);
    assert_eq!(got, want);
}

#[test]
fn an_unaligned_range_covers_every_block_it_touches() {
    let (mut v, ino) = with_file(1);
    v.fallocate(ino, 0, B + 10, 20).expect("allocate");
    let inode = v.read_inode(ino).expect("inode");
    assert_eq!(inode.size, B + 30);
    assert_eq!(inode.blocks, 3, "the inode's own block, block zero and block one");
}

#[test]
fn a_zero_length_request_does_nothing_at_all() {
    let (mut v, ino) = with_file(2);
    let inode = v.read_inode(ino).expect("inode");
    v.fallocate(ino, 0, 4 * B, 0).expect("allocate");
    let after = v.read_inode(ino).expect("inode");
    assert_eq!((after.size, after.blocks), (inode.size, inode.blocks));
}

#[test]
fn a_range_past_what_the_format_can_address_is_refused() {
    let (mut v, ino) = with_file(1);
    let top = v.max_file_bytes(ino).expect("max");
    assert_eq!(v.fallocate(ino, 0, top, B), Err(Errno::Efbig));
    assert_eq!(v.fallocate(ino, 0, u64::MAX - 1, 4), Err(Errno::Efbig));
}

#[test]
fn a_file_living_inside_its_inode_moves_out_when_it_is_given_blocks() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"small", &spec(), None).expect("create");
    v.write_file(ino, 0, b"abcdefghij").expect("write");
    assert!(v.read_inode(ino).expect("inode").inline_data());
    v.fallocate(ino, 0, 0, 2 * B).expect("allocate");
    assert!(!v.read_inode(ino).expect("inode").inline_data());
    let (_, got) = settled(v, ino);
    let mut want = b"abcdefghij".to_vec();
    want.extend(vec![0u8; 2 * BLKSIZE - 10]);
    assert_eq!(got, want);
}
