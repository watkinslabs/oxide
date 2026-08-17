//! A whole move: both inodes, their lengths, their block counts, remounted.

use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;
use syscall::errno::Errno;

use crate::mode::{S_IFDIR, S_IFREG};
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 7);
const BLK: u64 = BLKSIZE as u64;

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

fn page(tag: u8) -> Vec<u8> { vec![tag; BLKSIZE] }

fn file(v: &mut Volume<MemImage>, name: &[u8], tags: &[u8]) -> u32 {
    let ino = v.create(ROOT_INO, name, &spec(), None).unwrap();
    for (i, t) in tags.iter().enumerate() {
        v.write_file(ino, i as u64 * BLK, &page(*t)).unwrap();
        v.sync_data().unwrap();
    }
    ino
}

fn remount(mut v: Volume<MemImage>) -> Volume<MemImage> {
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

fn tags(v: &Volume<MemImage>, ino: u32, n: u64) -> Vec<u8> {
    let inode = v.read_inode(ino).unwrap();
    let mut out = vec![0u8; (n * BLK) as usize];
    v.read_file(&inode, ino, 0, &mut out).unwrap();
    (0..n).map(|i| out[(i * BLK) as usize]).collect()
}

fn pair() -> (Volume<MemImage>, u32, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let src = file(&mut v, b"a", &[1, 2, 3, 4]);
    let dst = file(&mut v, b"b", &[9, 9]);
    (v, src, dst)
}

// ------------------------------------------------------------------- the move

#[test]
fn a_move_lands_where_it_was_aimed_and_survives_a_remount() {
    let (mut v, src, dst) = pair();
    v.move_file_range(src, BLK, dst, 0, 2 * BLK).unwrap();
    let v = remount(v);
    assert_eq!(tags(&v, dst, 2), vec![2, 3]);
    assert_eq!(tags(&v, src, 4), vec![1, 0, 0, 4]);
}

#[test]
fn the_destination_grows_to_exactly_what_was_asked_for() {
    let (mut v, src, dst) = pair();
    v.move_file_range(src, 0, dst, 2 * BLK, 2 * BLK).unwrap();
    assert_eq!(v.read_inode(dst).unwrap().size, 4 * BLK);
    let v = remount(v);
    assert_eq!(tags(&v, dst, 4), vec![9, 9, 1, 2]);
}

#[test]
fn a_destination_that_already_reaches_further_keeps_its_length() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let src = file(&mut v, b"a", &[1, 2]);
    let dst = file(&mut v, b"b", &[9, 9, 9, 9]);
    let was = v.read_inode(dst).unwrap().size;
    v.move_file_range(src, 0, dst, 0, BLK).unwrap();
    assert_eq!(v.read_inode(dst).unwrap().size, was);
}

#[test]
fn the_source_keeps_its_length_and_loses_its_blocks() {
    let (mut v, src, dst) = pair();
    let before = v.read_inode(src).unwrap();
    v.move_file_range(src, 0, dst, 0, 2 * BLK).unwrap();
    let after = v.read_inode(src).unwrap();
    assert_eq!(after.size, before.size);
    assert_eq!(after.blocks, before.blocks - 2);
}

#[test]
fn the_destination_gains_exactly_the_blocks_the_source_lost() {
    let (mut v, src, dst) = pair();
    let before = v.read_inode(dst).unwrap().blocks;
    // Two of the destination's own blocks are replaced, so its count is the
    // same and the source's is two lower.
    v.move_file_range(src, 0, dst, 0, 2 * BLK).unwrap();
    assert_eq!(v.read_inode(dst).unwrap().blocks, before);
    assert_eq!(v.read_inode(src).unwrap().blocks, 3);
}

#[test]
fn a_length_of_zero_takes_the_rest_of_the_source() {
    let (mut v, src, dst) = pair();
    v.move_file_range(src, 2 * BLK, dst, 0, 0).unwrap();
    let v = remount(v);
    assert_eq!(tags(&v, dst, 2), vec![3, 4]);
}

#[test]
fn moving_a_range_onto_itself_changes_nothing() {
    let (mut v, src, _) = pair();
    let before = (0..4).map(|i| v.mapped_addr(src, i).unwrap()).collect::<Vec<_>>();
    v.move_file_range(src, BLK, src, BLK, 2 * BLK).unwrap();
    assert_eq!((0..4).map(|i| v.mapped_addr(src, i).unwrap()).collect::<Vec<_>>(), before);
}

#[test]
fn a_move_backwards_inside_one_file() {
    let (mut v, src, _) = pair();
    v.move_file_range(src, 2 * BLK, src, 0, 2 * BLK).unwrap();
    let v = remount(v);
    assert_eq!(tags(&v, src, 4), vec![3, 4, 0, 0]);
}

#[test]
fn a_move_into_an_empty_file_gives_it_the_bytes() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let src = file(&mut v, b"a", &[1, 2]);
    let dst = v.create(ROOT_INO, b"b", &spec(), None).unwrap();
    v.move_file_range(src, 0, dst, 0, 2 * BLK).unwrap();
    assert_eq!(v.read_inode(dst).unwrap().size, 2 * BLK);
    let v = remount(v);
    assert_eq!(tags(&v, dst, 2), vec![1, 2]);
}

#[test]
fn an_inline_source_is_moved_out_into_blocks_first() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let src = v.create(ROOT_INO, b"a", &spec(), None).unwrap();
    v.write_file(src, 0, b"inline bytes").unwrap();
    v.sync_data().unwrap();
    assert!(v.read_inode(src).unwrap().inline_data());
    let dst = v.create(ROOT_INO, b"b", &spec(), None).unwrap();
    v.move_file_range(src, 0, dst, 0, 0).unwrap();
    let v = remount(v);
    let inode = v.read_inode(dst).unwrap();
    let mut out = vec![0u8; 12];
    v.read_file(&inode, dst, 0, &mut out).unwrap();
    assert_eq!(&out, b"inline bytes");
}

// ---------------------------------------------------------------- the refusals

#[test]
fn a_read_only_mount_refuses() {
    let mut v = test_image::with_root().mount().unwrap();
    assert_eq!(v.move_file_range(ROOT_INO, 0, ROOT_INO, BLK, BLK), Err(Errno::Erofs));
}

#[test]
fn a_directory_at_either_end_is_refused() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let src = file(&mut v, b"a", &[1, 2]);
    let dir = v.create(ROOT_INO, b"d", &NewInode { mode: S_IFDIR | 0o755, ..spec() }, None)
        .unwrap();
    assert_eq!(v.move_file_range(src, 0, dir, 0, BLK), Err(Errno::Einval));
    assert_eq!(v.move_file_range(dir, 0, src, 0, BLK), Err(Errno::Einval));
}

#[test]
fn a_pinned_end_can_never_do_this() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let src = file(&mut v, b"a", &[1, 2]);
    let dst = v.create(ROOT_INO, b"b", &spec(), None).unwrap();
    v.set_pinned(dst, true).unwrap();
    assert_eq!(v.move_file_range(src, 0, dst, 0, BLK), Err(Errno::Eopnotsupp));
}

#[test]
fn an_end_in_an_atomic_span_is_refused() {
    let (mut v, src, dst) = pair();
    v.start_atomic_write(dst, false).unwrap();
    assert_eq!(v.move_file_range(src, 0, dst, 0, BLK), Err(Errno::Einval));
}

#[test]
fn an_unaligned_request_is_refused_and_moves_nothing() {
    let (mut v, src, dst) = pair();
    let before = (0..4).map(|i| v.mapped_addr(src, i).unwrap()).collect::<Vec<_>>();
    assert_eq!(v.move_file_range(src, 1, dst, 0, BLK), Err(Errno::Einval));
    assert_eq!(v.move_file_range(src, 0, dst, 1, BLK), Err(Errno::Einval));
    assert_eq!((0..4).map(|i| v.mapped_addr(src, i).unwrap()).collect::<Vec<_>>(), before);
}

#[test]
fn a_range_past_the_end_of_the_source_is_refused() {
    let (mut v, src, dst) = pair();
    assert_eq!(v.move_file_range(src, 2 * BLK, dst, 0, 4 * BLK), Err(Errno::Einval));
}

#[test]
fn a_forward_overlap_inside_one_file_is_refused() {
    let (mut v, src, _) = pair();
    assert_eq!(v.move_file_range(src, 0, src, BLK, 2 * BLK), Err(Errno::Einval));
}
