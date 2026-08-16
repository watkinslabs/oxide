//! The one entry point: which operation each mode reaches, and the refusals
//! that get there before any of them.

use super::*;
use crate::fallocate::uapi::*;
use crate::mode::S_IFDIR;

const B: u64 = BLKSIZE as u64;

#[test]
fn keep_size_alone_reaches_the_plain_allocation() {
    // It is a modifier, not a sixth request; a dispatch that treated it as one
    // would make `fallocate(KEEP_SIZE)` do nothing.
    let (mut v, ino) = with_file(1);
    v.fallocate(ino, FALLOC_FL_KEEP_SIZE, B, B).expect("allocate");
    assert_eq!(v.read_inode(ino).expect("inode").blocks, 3);
}

#[test]
fn each_operation_bit_reaches_its_own_operation() {
    let (mut v, ino) = with_file(4);
    // Punch frees; zero does not; collapse shortens; insert lengthens.
    let n = |v: &Volume<MemImage>| v.read_inode(ino).expect("inode").blocks;
    let s = |v: &Volume<MemImage>| v.read_inode(ino).expect("inode").size;
    let (b0, s0) = (n(&v), s(&v));
    v.fallocate(ino, FALLOC_FL_PUNCH_HOLE, B, B).expect("punch");
    assert_eq!((n(&v), s(&v)), (b0 - 1, s0));
    v.fallocate(ino, FALLOC_FL_ZERO_RANGE, B, B).expect("zero");
    assert_eq!((n(&v), s(&v)), (b0, s0));
    v.fallocate(ino, FALLOC_FL_COLLAPSE_RANGE, B, B).expect("collapse");
    assert_eq!(s(&v), s0 - B);
    v.fallocate(ino, FALLOC_FL_INSERT_RANGE, B, B).expect("insert");
    assert_eq!(s(&v), s0);
}

#[test]
fn a_directory_is_refused_before_anything_is_touched() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let dir = NewInode { mode: S_IFDIR | 0o755, ..spec() };
    let sub = v.create(ROOT_INO, b"d", &dir, None).expect("mkdir");
    let before = v.read_inode(sub).expect("inode").blocks;
    for m in [0, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE, FALLOC_FL_COLLAPSE_RANGE,
              FALLOC_FL_INSERT_RANGE] {
        assert_eq!(v.fallocate(sub, m, 0, B), Err(Errno::Einval), "mode {m:#x}");
    }
    assert_eq!(v.read_inode(sub).expect("inode").blocks, before);
}

#[test]
fn an_unknown_mode_bit_is_refused() {
    let (mut v, ino) = with_file(1);
    assert_eq!(v.fallocate(ino, 0x04, 0, B), Err(Errno::Eopnotsupp));
    assert_eq!(v.fallocate(ino, 1 << 30, 0, B), Err(Errno::Eopnotsupp));
}

#[test]
fn a_pinned_file_refuses_every_partial_operation_and_takes_the_allocation() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"pin", &spec(), None).expect("create");
    v.set_pinned(ino, true).expect("pin");
    for m in [FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE, FALLOC_FL_COLLAPSE_RANGE,
              FALLOC_FL_INSERT_RANGE] {
        assert_eq!(v.fallocate(ino, m, 0, B), Err(Errno::Eopnotsupp), "mode {m:#x}");
    }
    let sec = u64::from(v.blks_per_sec()) * B;
    v.fallocate(ino, 0, 0, sec).expect("the pinned allocation is what pinning is for");
    assert!(v.read_inode(ino).expect("inode").blocks > 1);
}

#[test]
fn a_pinned_allocation_keeping_the_size_leaves_the_length_alone() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"pin", &spec(), None).expect("create");
    v.set_pinned(ino, true).expect("pin");
    let sec = u64::from(v.blks_per_sec()) * B;
    v.fallocate(ino, FALLOC_FL_KEEP_SIZE, 0, sec).expect("allocate");
    let inode = v.read_inode(ino).expect("inode");
    assert_eq!(inode.size, 0, "the length did not move");
    assert!(inode.blocks > 1, "and the blocks are there");
}

#[test]
fn a_read_only_mount_refuses_every_mode() {
    let v = test_image::with_root().mount_rw().expect("mount");
    let bytes = v.into_source().snapshot();
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes);
    let mut v = Volume::mount_with(img, Options::defaults(), false).expect("mount ro");
    assert_eq!(v.fallocate(ROOT_INO, 0, 0, B), Err(Errno::Erofs));
}

#[test]
fn a_range_that_overflows_is_refused_rather_than_wrapping() {
    let (mut v, ino) = with_file(1);
    assert_eq!(v.fallocate(ino, FALLOC_FL_KEEP_SIZE, u64::MAX, 2), Err(Errno::Efbig));
}
