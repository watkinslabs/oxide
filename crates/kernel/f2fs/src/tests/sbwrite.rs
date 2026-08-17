//! The superblock writer against a whole volume: a change written, and the
//! MEDIUM's bytes mounted again.
//!
//! Reading a field back out of the structure that was just edited proves
//! nothing — it is the same memory. Every test here goes through the medium:
//! commit, then mount the bytes, then ask the mount. That is the only way the
//! checksum, the copy positions and the block-preserving write are all in the
//! path being checked.

use alloc::vec;
use alloc::vec::Vec;

use core::cell::RefCell;

use sectors::{MemImage, SectorSource};
use syscall::errno::Errno;

use crate::opts::Options;
use crate::sbflags::{bits, SbFlags};
use crate::sbwrite::{commit_super, edit, read_raw};
use crate::test_image;
use crate::uapi::*;
use crate::volume::Volume;

/// A medium that records the order of its writes, and can be told to fail one
/// — which is how a crash between the two copies is put under a test.
pub struct Recorder {
    inner: MemImage,
    writes: RefCell<Vec<u64>>,
    fail_after: usize,
}

impl Recorder {
    fn new(bytes: Vec<u8>, fail_after: usize) -> Self {
        Self { inner: MemImage::from_bytes(BLKSIZE as u32, bytes), writes: RefCell::new(Vec::new()),
               fail_after }
    }

    fn order(&self) -> Vec<u64> { self.writes.borrow().clone() }

    fn into_bytes(self) -> Vec<u8> { self.inner.snapshot() }
}

impl SectorSource for Recorder {
    fn read_sectors(&self, sector: u64, buf: &mut [u8]) -> Result<(), Errno> {
        self.inner.read_sectors(sector, buf)
    }

    fn write_sectors(&self, sector: u64, buf: &[u8]) -> Result<(), Errno> {
        if self.writes.borrow().len() >= self.fail_after { return Err(Errno::Eio); }
        self.writes.borrow_mut().push(sector);
        self.inner.write_sectors(sector, buf)
    }

    fn writable(&self) -> bool { true }
}

/// A formatted volume's bytes.
fn bytes() -> Vec<u8> { test_image::with_root().finish() }

/// The label a mount of `bytes` reports.
fn label_of(bytes: Vec<u8>) -> alloc::string::String {
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes);
    let v: Volume<MemImage> = Volume::mount_with(img, Options::defaults(), false).expect("mount");
    v.super_block().volume_name.clone()
}

// ------------------------------------------------------- which copy is which

#[test]
fn a_sound_volume_believes_the_first_copy_and_owes_no_repair() {
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes());
    let (raw, sb) = read_raw(&img).expect("read");
    assert_eq!(raw.valid(), 0);
    assert!(!raw.recovery());
    assert_eq!(sb.volume_name, "oxide");
}

#[test]
fn a_broken_first_copy_moves_belief_to_the_second_and_owes_a_repair() {
    let mut b = test_image::with_root();
    b.break_super0 = true;
    let img = MemImage::from_bytes(BLKSIZE as u32, b.finish());
    let (raw, sb) = read_raw(&img).expect("read");
    assert_eq!(raw.valid(), 1);
    assert!(raw.recovery(), "the bad copy is owed a repair");
    assert_eq!(sb.volume_name, "oxide");
}

#[test]
fn a_broken_second_copy_is_a_repair_owed_too() {
    // The believed copy is the first one, so a reader that stopped as soon as
    // it had a good copy would never learn the other is bad.
    let mut start = bytes();
    start[BLKSIZE + SUPER_OFFSET + SB_VOLUME_NAME] ^= 0xFF;
    let img = MemImage::from_bytes(BLKSIZE as u32, start);
    let (raw, _) = read_raw(&img).expect("read");
    assert_eq!(raw.valid(), 0);
    assert!(raw.recovery(), "the copy after the believed one is examined too");
}

#[test]
fn both_copies_broken_is_refused() {
    let mut raw = bytes();
    for copy in 0..SUPER_COPIES as usize {
        raw[copy * BLKSIZE + SUPER_OFFSET + SB_VOLUME_NAME] ^= 0xFF;
    }
    let img = MemImage::from_bytes(BLKSIZE as u32, raw);
    assert!(read_raw(&img).is_err());
}

// ----------------------------------------------------- a change reaches disk

#[test]
fn a_label_written_is_the_label_the_next_mount_reads() {
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes());
    let (mut raw, _) = read_raw(&img).expect("read");
    edit::set_volume_name(&mut raw, "relabelled").expect("label");
    let mut flags = SbFlags::new();
    commit_super(&img, &mut raw, false, false, &mut flags).expect("commit");
    assert_eq!(label_of(img.snapshot()), "relabelled");
}

#[test]
fn an_extension_written_is_in_the_list_the_next_mount_reads() {
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes());
    let (mut raw, _) = read_raw(&img).expect("read");
    edit::update_extension_list(&mut raw, "iso", false, true).expect("add");
    edit::update_extension_list(&mut raw, "log", true, true).expect("add hot");
    let mut flags = SbFlags::new();
    commit_super(&img, &mut raw, false, false, &mut flags).expect("commit");

    let mounted = MemImage::from_bytes(BLKSIZE as u32, img.snapshot());
    let v: Volume<MemImage> =
        Volume::mount_with(mounted, Options::defaults(), false).expect("mount");
    let sb = v.super_block();
    assert_eq!(sb.extension_count, 3);
    assert_eq!(sb.hot_ext_count, 1);
    // Both halves, in one array: the cold ones the count names, then the hot
    // one after them. A list that stopped at the cold count would report the
    // hot entry as absent on every later mount.
    assert_eq!(sb.extensions, vec!["jpg", "mp4", "iso", "log"]);
}

#[test]
fn a_change_without_a_commit_never_reaches_the_medium() {
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes());
    let (mut raw, _) = read_raw(&img).expect("read");
    edit::set_volume_name(&mut raw, "only-in-memory").expect("label");
    assert_eq!(label_of(img.snapshot()), "oxide");
}

#[test]
fn the_boot_area_ahead_of_the_first_copy_survives_a_commit() {
    let mut start = bytes();
    for (i, b) in start[..SUPER_OFFSET].iter_mut().enumerate() { *b = i as u8; }
    let img = MemImage::from_bytes(BLKSIZE as u32, start);
    let (mut raw, _) = read_raw(&img).expect("read");
    edit::set_volume_name(&mut raw, "boot").expect("label");
    let mut flags = SbFlags::new();
    commit_super(&img, &mut raw, false, false, &mut flags).expect("commit");
    let after = img.snapshot();
    assert!(after[..SUPER_OFFSET].iter().enumerate().all(|(i, &b)| b == i as u8),
            "the bytes ahead of the superblock are not the writer's to touch");
}

// ------------------------------------------------------------- crash and RO

#[test]
fn a_crash_between_the_two_copies_leaves_the_volume_as_it_was() {
    // One write lands — the backup — and the second fails, which is what a
    // power loss between them looks like to the next mount.
    let rec = Recorder::new(bytes(), 1);
    let (mut raw, _) = read_raw(&rec).expect("read");
    edit::set_volume_name(&mut raw, "half-written").expect("label");
    let mut flags = SbFlags::new();
    assert_eq!(commit_super(&rec, &mut raw, false, false, &mut flags), Err(Errno::Eio));
    assert_eq!(rec.order(), vec![1], "the copy that is NOT believed goes first");
    assert_eq!(label_of(rec.into_bytes()), "oxide");
}

#[test]
fn both_copies_are_written_and_the_believed_one_goes_last() {
    let rec = Recorder::new(bytes(), usize::MAX);
    let (mut raw, _) = read_raw(&rec).expect("read");
    edit::set_volume_name(&mut raw, "both").expect("label");
    let mut flags = SbFlags::new();
    commit_super(&rec, &mut raw, false, false, &mut flags).expect("commit");
    assert_eq!(rec.order(), vec![1, 0]);
    let after = rec.into_bytes();
    for copy in 0..SUPER_COPIES as usize {
        let at = copy * BLKSIZE + SUPER_OFFSET;
        assert_eq!(&after[at..at + SUPER_SIZE], raw.bytes(), "copy {copy}");
    }
}

#[test]
fn a_repair_writes_the_bad_copy_and_leaves_the_good_one_alone() {
    let mut b = test_image::with_root();
    b.break_super0 = true;
    let rec = Recorder::new(b.finish(), usize::MAX);
    let before = rec.inner.peek(BLKSIZE + SUPER_OFFSET, SUPER_SIZE);
    let (mut raw, _) = read_raw(&rec).expect("read");
    assert!(raw.recovery());
    let mut flags = SbFlags::new();
    commit_super(&rec, &mut raw, true, false, &mut flags).expect("repair");
    assert_eq!(rec.order(), vec![0], "only the copy being repaired is written");
    let after = rec.into_bytes();
    assert_eq!(&after[BLKSIZE + SUPER_OFFSET..BLKSIZE + SUPER_OFFSET + SUPER_SIZE], &before[..],
               "the copy being copied from is untouched");
    // And the volume no longer owes a repair.
    let img = MemImage::from_bytes(BLKSIZE as u32, after);
    let (raw, _) = read_raw(&img).expect("read");
    assert_eq!(raw.valid(), 0);
    assert!(!raw.recovery());
}

#[test]
fn a_medium_that_refuses_writes_leaves_the_write_owed() {
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes()).read_only();
    let (mut raw, _) = read_raw(&img).expect("read");
    edit::set_volume_name(&mut raw, "nowhere").expect("label");
    let mut flags = SbFlags::new();
    assert_eq!(commit_super(&img, &mut raw, false, false, &mut flags), Err(Errno::Erofs));
    assert!(flags.is_set(bits::NEED_SB_WRITE));
    assert_eq!(label_of(img.snapshot()), "oxide");
}

#[test]
fn a_repair_is_refused_on_a_read_only_mount_and_left_owed() {
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes());
    let (mut raw, _) = read_raw(&img).expect("read");
    let mut flags = SbFlags::new();
    assert_eq!(commit_super(&img, &mut raw, true, true, &mut flags), Err(Errno::Erofs));
    assert!(flags.is_set(bits::NEED_SB_WRITE));
}

#[test]
fn an_ordinary_change_is_allowed_while_the_mount_is_read_only() {
    // A remount that is turning the volume writable commits before the mount
    // itself is writable; refusing there would make the write unreachable.
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes());
    let (mut raw, _) = read_raw(&img).expect("read");
    edit::set_volume_name(&mut raw, "remounted").expect("label");
    let mut flags = SbFlags::new();
    commit_super(&img, &mut raw, false, true, &mut flags).expect("commit");
    assert!(!flags.is_set(bits::NEED_SB_WRITE));
    assert_eq!(label_of(img.snapshot()), "remounted");
}

// --------------------------------------------------------------- the seal

#[test]
fn a_committed_copy_carries_a_checksum_over_its_new_bytes() {
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes());
    let (mut raw, _) = read_raw(&img).expect("read");
    let was = le32(raw.bytes(), SB_CRC).expect("crc");
    edit::set_volume_name(&mut raw, "sealed").expect("label");
    let mut flags = SbFlags::new();
    commit_super(&img, &mut raw, false, false, &mut flags).expect("commit");
    let now = le32(raw.bytes(), SB_CRC).expect("crc");
    assert_ne!(was, now, "the seal covers the label");
    assert!(crate::checksum::super_ok(raw.bytes()));
    // The proof the seal is right is that a mount accepts the copy at all: a
    // wrong CRC fails the copy's checks and the volume would fall back or
    // refuse.
    assert_eq!(label_of(img.snapshot()), "sealed");
}

#[test]
fn a_repair_does_not_reseal_what_it_copies() {
    let mut b = test_image::with_root();
    b.break_super0 = true;
    let img = MemImage::from_bytes(BLKSIZE as u32, b.finish());
    let (mut raw, _) = read_raw(&img).expect("read");
    let was = le32(raw.bytes(), SB_CRC).expect("crc");
    let mut flags = SbFlags::new();
    commit_super(&img, &mut raw, true, false, &mut flags).expect("repair");
    assert_eq!(le32(raw.bytes(), SB_CRC), Some(was));
}
