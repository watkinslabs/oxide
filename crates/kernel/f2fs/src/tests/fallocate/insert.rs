//! `INSERT_RANGE`: a gap opens and everything after it moves along.

use super::*;
use crate::fallocate::FALLOC_FL_INSERT_RANGE;

const I: u32 = FALLOC_FL_INSERT_RANGE;
const B: u64 = BLKSIZE as u64;

#[test]
fn the_bytes_after_the_point_move_up_and_the_gap_reads_as_zeroes() {
    let (mut v, ino) = with_file(3);
    v.fallocate(ino, I, B, B).expect("insert");
    let (_, got) = settled(v, ino);
    let mut want = vec![1u8; BLKSIZE];
    want.extend(vec![0u8; BLKSIZE]);
    want.extend(vec![2u8; BLKSIZE]);
    want.extend(vec![3u8; BLKSIZE]);
    assert_eq!(got, want);
}

#[test]
fn the_file_grows_by_exactly_the_length_inserted() {
    let (mut v, ino) = with_file(3);
    let size = v.read_inode(ino).expect("inode").size;
    v.fallocate(ino, I, B, 2 * B).expect("insert");
    assert_eq!(v.read_inode(ino).expect("inode").size, size + 2 * B);
}

#[test]
fn the_gap_is_a_hole_and_costs_no_blocks() {
    let (mut v, ino) = with_file(3);
    let before = v.read_inode(ino).expect("inode").blocks;
    v.fallocate(ino, I, B, 2 * B).expect("insert");
    assert_eq!(v.read_inode(ino).expect("inode").blocks, before,
               "inserting a gap allocates nothing");
}

#[test]
fn inserting_at_the_head_pushes_the_whole_file_along() {
    let (mut v, ino) = with_file(2);
    v.fallocate(ino, I, 0, B).expect("insert");
    let (_, got) = settled(v, ino);
    let mut want = vec![0u8; BLKSIZE];
    want.extend(pattern(2));
    assert_eq!(got, want);
}

#[test]
fn an_offset_at_or_past_the_end_is_refused() {
    // Nothing after it to move, so the request is an ordinary extension.
    let (mut v, ino) = with_file(2);
    assert_eq!(v.fallocate(ino, I, 2 * B, B), Err(Errno::Einval));
    assert_eq!(v.fallocate(ino, I, 9 * B, B), Err(Errno::Einval));
    assert!(v.fallocate(ino, I, B, B).is_ok());
}

#[test]
fn an_unaligned_end_is_refused() {
    let (mut v, ino) = with_file(3);
    assert_eq!(v.fallocate(ino, I, 1, B), Err(Errno::Einval));
    assert_eq!(v.fallocate(ino, I, B, B + 1), Err(Errno::Einval));
}

#[test]
fn an_insert_across_a_direct_node_boundary_keeps_every_byte() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"wide", &spec(), None).expect("create");
    let apb = v.read_inode(ino).expect("inode").addrs_per_inode() as u64;
    let blocks = (apb + 3) as usize;
    v.write_file(ino, 0, &pattern(blocks)).expect("write");
    v.commit().expect("commit");
    // The gap opens at the last slot of the inode's own array, so the run that
    // moves up starts in the inode and lands in a direct node.
    v.fallocate(ino, I, (apb - 1) * B, B).expect("insert");
    let (_, got) = settled(v, ino);
    let full = pattern(blocks);
    let mut want = full[..((apb - 1) as usize) * BLKSIZE].to_vec();
    want.extend(vec![0u8; BLKSIZE]);
    want.extend_from_slice(&full[((apb - 1) as usize) * BLKSIZE..]);
    assert_eq!(got.len(), want.len());
    assert_eq!(got, want);
}

#[test]
fn an_insert_undone_by_a_collapse_leaves_the_file_as_it_was() {
    // The two are inverses, which is the strongest single statement about the
    // direction each walk takes: one walk in the wrong order loses a block and
    // the round trip shows it.
    let (mut v, ino) = with_file(5);
    let before = pattern(5);
    v.fallocate(ino, I, 2 * B, 2 * B).expect("insert");
    v.fallocate(ino, crate::fallocate::FALLOC_FL_COLLAPSE_RANGE, 2 * B, 2 * B)
        .expect("collapse");
    let (_, got) = settled(v, ino);
    assert_eq!(got, before);
}
