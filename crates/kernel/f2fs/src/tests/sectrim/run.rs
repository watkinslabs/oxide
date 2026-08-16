//! Erasing a file's blocks in place: what is destroyed, and what is not.

use alloc::vec;
use alloc::vec::Vec;

use sectors::{MemImage, SectorSource};
use syscall::errno::Errno;

use crate::ioctl::uapi::{TRIM_FILE_DISCARD, TRIM_FILE_ZEROOUT};
use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 7);
const BLK: u64 = BLKSIZE as u64;

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

fn page(tag: u8) -> Vec<u8> { vec![tag; BLKSIZE] }

fn with_file(tags: &[u8]) -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    for (i, t) in tags.iter().enumerate() {
        v.write_file(ino, i as u64 * BLK, &page(*t)).unwrap();
    }
    (v, ino)
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

// ------------------------------------------------------------------- the erase

#[test]
fn zeroing_destroys_the_bytes_and_keeps_the_file() {
    let (mut v, ino) = with_file(&[1, 2, 3]);
    let before = v.read_inode(ino).unwrap();
    let addrs = (0..3).map(|i| v.mapped_addr(ino, i).unwrap()).collect::<Vec<_>>();
    v.sec_trim_file(ino, 0, 3 * BLK, TRIM_FILE_ZEROOUT).unwrap();
    let after = v.read_inode(ino).unwrap();
    // Same length, same blocks, same addresses — only the contents are gone.
    assert_eq!(after.size, before.size);
    assert_eq!(after.blocks, before.blocks);
    assert_eq!((0..3).map(|i| v.mapped_addr(ino, i).unwrap()).collect::<Vec<_>>(), addrs);
    let v = remount(v);
    assert_eq!(tags(&v, ino, 3), vec![0, 0, 0]);
}

#[test]
fn only_the_named_blocks_are_erased() {
    let (mut v, ino) = with_file(&[1, 2, 3, 4]);
    v.sec_trim_file(ino, BLK, 2 * BLK, TRIM_FILE_ZEROOUT).unwrap();
    let v = remount(v);
    assert_eq!(tags(&v, ino, 4), vec![1, 0, 0, 4]);
}

#[test]
fn a_discard_reaches_the_medium_as_one_run_of_the_blocks_it_named() {
    let (mut v, ino) = with_file(&[1, 2, 3]);
    let first = v.mapped_addr(ino, 0).unwrap().unwrap();
    v.sec_trim_file(ino, 0, 3 * BLK, TRIM_FILE_DISCARD).unwrap();
    // Contiguous blocks are one request: a device erases in large units and a
    // request of one block is nearly all overhead.
    assert_eq!(v.source.erased(), vec![(u64::from(first), 3)]);
}

#[test]
fn blocks_that_are_not_adjacent_on_the_medium_are_separate_requests() {
    // Written out of order, so the file's blocks are scattered: a single run
    // would name blocks belonging to something else.
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    for index in [1u64, 0] { v.write_file(ino, index * BLK, &page(index as u8 + 1)).unwrap(); }
    v.sec_trim_file(ino, 0, 2 * BLK, TRIM_FILE_DISCARD).unwrap();
    let erased = v.source.erased();
    assert_eq!(erased.len(), 2, "expected two runs, got {erased:?}");
    assert!(erased.iter().all(|&(_, n)| n == 1));
}

#[test]
fn a_hole_does_not_reach_the_medium() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &page(1)).unwrap();
    v.write_file(ino, 2 * BLK, &page(3)).unwrap();
    v.sec_trim_file(ino, 0, 3 * BLK, TRIM_FILE_DISCARD).unwrap();
    let erased = v.source.erased();
    assert_eq!(erased.iter().map(|&(_, n)| n).sum::<u64>(), 2);
}

#[test]
fn asking_for_both_erases_and_then_zeroes() {
    let (mut v, ino) = with_file(&[1, 2]);
    v.sec_trim_file(ino, 0, 2 * BLK, TRIM_FILE_DISCARD | TRIM_FILE_ZEROOUT).unwrap();
    assert_eq!(v.source.erased().len(), 1);
    let v = remount(v);
    assert_eq!(tags(&v, ino, 2), vec![0, 0]);
}

#[test]
fn a_range_reaching_the_end_takes_the_last_partial_block_whole() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &page(1)).unwrap();
    v.write_file(ino, BLK, &[7u8; 8]).unwrap();
    assert_eq!(v.read_inode(ino).unwrap().size, BLK + 8);
    v.sec_trim_file(ino, BLK, u64::MAX, TRIM_FILE_ZEROOUT).unwrap();
    let v = remount(v);
    assert_eq!(tags(&v, ino, 2), vec![1, 0]);
}

#[test]
fn a_length_of_zero_erases_nothing() {
    let (mut v, ino) = with_file(&[1, 2]);
    v.sec_trim_file(ino, 0, 0, TRIM_FILE_DISCARD).unwrap();
    assert!(v.source.erased().is_empty());
}

// ---------------------------------------------------------------- the refusals

#[test]
fn a_read_only_mount_refuses() {
    let mut v = test_image::with_root().mount().unwrap();
    assert_eq!(v.sec_trim_file(ROOT_INO, 0, BLK, TRIM_FILE_ZEROOUT), Err(Errno::Erofs));
}

#[test]
fn no_method_at_all_is_refused() {
    let (mut v, ino) = with_file(&[1]);
    assert_eq!(v.sec_trim_file(ino, 0, BLK, 0), Err(Errno::Einval));
}

#[test]
fn a_method_that_does_not_exist_is_refused() {
    let (mut v, ino) = with_file(&[1]);
    assert_eq!(v.sec_trim_file(ino, 0, BLK, 0x4), Err(Errno::Einval));
}

#[test]
fn a_start_past_the_end_is_refused() {
    let (mut v, ino) = with_file(&[1]);
    assert_eq!(v.sec_trim_file(ino, 4 * BLK, BLK, TRIM_FILE_ZEROOUT), Err(Errno::Einval));
}

#[test]
fn an_unaligned_request_stopping_short_of_the_end_is_refused() {
    let (mut v, ino) = with_file(&[1, 2, 3]);
    assert_eq!(v.sec_trim_file(ino, 0, BLK + 1, TRIM_FILE_ZEROOUT), Err(Errno::Einval));
    // And nothing was erased on the way to being told so.
    assert_eq!(tags(&v, ino, 3), vec![1, 2, 3]);
}

#[test]
fn a_medium_that_cannot_erase_says_so_rather_than_reporting_success() {
    // The default answer for a medium with no erase, which is the honest one:
    // a caller asking for a discard is asking for the bytes to be GONE.
    struct NoErase(MemImage);
    impl SectorSource for NoErase {
        fn read_sectors(&self, s: u64, b: &mut [u8]) -> Result<(), Errno> {
            self.0.read_sectors(s, b)
        }
        fn write_sectors(&self, s: u64, b: &[u8]) -> Result<(), Errno> {
            self.0.write_sectors(s, b)
        }
        fn writable(&self) -> bool { true }
    }
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &page(1)).unwrap();
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    let src = NoErase(MemImage::from_bytes(BLKSIZE as u32, bytes));
    let mut v = Volume::mount_with(src, Options::defaults(), true).unwrap();
    assert_eq!(v.sec_trim_file(ino, 0, BLK, TRIM_FILE_DISCARD), Err(Errno::Eopnotsupp));
}
