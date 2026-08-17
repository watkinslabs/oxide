//! The last index a file holds anything at, found over its tree.

use alloc::vec;
use alloc::vec::Vec;

use crate::mode::S_IFREG;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::NewInode;

const NOW: (u64, u32) = (1_800_000_000, 7);
const BLK: u64 = BLKSIZE as u64;

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

fn page() -> Vec<u8> { vec![7u8; BLKSIZE] }

#[test]
fn a_file_with_nothing_in_blocks_has_no_highest_index() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    assert_eq!(v.highest_block_index(ino).unwrap(), None);
}

#[test]
fn the_inodes_own_array_answers_for_a_small_file() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    for i in 0..3u64 { v.write_file(ino, i * BLK, &page()).unwrap(); }
    assert_eq!(v.highest_block_index(ino).unwrap(), Some(2));
}

#[test]
fn a_hole_before_the_last_block_does_not_lower_the_answer() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &page()).unwrap();
    v.write_file(ino, 5 * BLK, &page()).unwrap();
    assert_eq!(v.highest_block_index(ino).unwrap(), Some(5));
}

#[test]
fn a_block_past_the_inodes_own_array_is_found_in_the_tree() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    let apb = v.read_inode(ino).unwrap().addrs_per_inode() as u64;
    v.write_file(ino, 0, &page()).unwrap();
    v.write_file(ino, (apb + 3) * BLK, &page()).unwrap();
    assert_eq!(v.highest_block_index(ino).unwrap(), Some(apb + 3));
}
