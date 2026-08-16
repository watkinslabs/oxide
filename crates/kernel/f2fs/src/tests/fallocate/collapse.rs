//! `COLLAPSE_RANGE`: the gap closes and the file gets shorter.

use super::*;
use crate::fallocate::FALLOC_FL_COLLAPSE_RANGE;

const C: u32 = FALLOC_FL_COLLAPSE_RANGE;
const B: u64 = BLKSIZE as u64;

#[test]
fn the_bytes_after_the_range_move_down_to_take_its_place() {
    let (mut v, ino) = with_file(4);
    v.fallocate(ino, C, B, B).expect("collapse");
    let (_, got) = settled(v, ino);
    // Blocks 1,2,3 of the pattern become blocks 0,1,2 minus the removed one.
    let mut want = Vec::new();
    for i in [0usize, 2, 3] { want.extend(vec![byte_for(i); BLKSIZE]); }
    assert_eq!(got, want);
}

#[test]
fn the_file_shortens_by_exactly_the_length_removed() {
    let (mut v, ino) = with_file(4);
    let size = v.read_inode(ino).expect("inode").size;
    v.fallocate(ino, C, B, 2 * B).expect("collapse");
    assert_eq!(v.read_inode(ino).expect("inode").size, size - 2 * B);
}

#[test]
fn the_removed_blocks_come_back() {
    let (mut v, ino) = with_file(4);
    let before = v.read_inode(ino).expect("inode").blocks;
    v.fallocate(ino, C, B, 2 * B).expect("collapse");
    assert_eq!(v.read_inode(ino).expect("inode").blocks, before - 2);
}

#[test]
fn collapsing_the_head_leaves_the_tail_at_offset_zero() {
    let (mut v, ino) = with_file(4);
    v.fallocate(ino, C, 0, 3 * B).expect("collapse");
    let (_, got) = settled(v, ino);
    assert_eq!(got, vec![byte_for(3); BLKSIZE]);
}

#[test]
fn a_range_reaching_the_end_is_refused() {
    // That is shortening, which has its own call and its own refusals.
    let (mut v, ino) = with_file(4);
    assert_eq!(v.fallocate(ino, C, 3 * B, B), Err(Errno::Einval));
    assert_eq!(v.fallocate(ino, C, 0, 4 * B), Err(Errno::Einval));
    assert_eq!(v.fallocate(ino, C, 2 * B, 10 * B), Err(Errno::Einval));
}

#[test]
fn an_unaligned_end_is_refused() {
    let (mut v, ino) = with_file(4);
    assert_eq!(v.fallocate(ino, C, 1, B), Err(Errno::Einval));
    assert_eq!(v.fallocate(ino, C, B, B + 1), Err(Errno::Einval));
    assert!(v.fallocate(ino, C, B, B).is_ok());
}

#[test]
fn a_hole_inside_the_moved_run_stays_a_hole_where_it_lands() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"sparse", &spec(), None).expect("create");
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).expect("block 0");
    v.write_file(ino, 3 * B, &vec![4u8; BLKSIZE]).expect("block 3");
    v.commit().expect("commit");
    // Remove block 0; blocks 1 and 2 are holes and block 3 moves to index 2.
    v.fallocate(ino, C, 0, B).expect("collapse");
    let (_, got) = settled(v, ino);
    let mut want = vec![0u8; 2 * BLKSIZE];
    want.extend(vec![4u8; BLKSIZE]);
    assert_eq!(got, want);
}

#[test]
fn a_collapse_across_a_direct_node_boundary_keeps_every_byte() {
    // The moves cross from the inode's own address array into a direct node,
    // which is where an off-by-one in the walk shows up.
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"wide", &spec(), None).expect("create");
    let apb = v.read_inode(ino).expect("inode").addrs_per_inode() as u64;
    let blocks = (apb + 3) as usize;
    v.write_file(ino, 0, &pattern(blocks)).expect("write");
    v.commit().expect("commit");
    // The removed block is the last one the inode's own array holds, so the
    // run that moves down starts in a direct node and lands in the inode.
    v.fallocate(ino, C, (apb - 1) * B, B).expect("collapse");
    let (_, got) = settled(v, ino);
    let full = pattern(blocks);
    let mut want = full[..((apb - 1) as usize) * BLKSIZE].to_vec();
    want.extend_from_slice(&full[(apb as usize) * BLKSIZE..]);
    assert_eq!(got.len(), want.len());
    assert_eq!(got, want);
}

