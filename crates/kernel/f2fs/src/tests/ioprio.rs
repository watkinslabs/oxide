//! The per-file write-priority hint, from the ioctl that sets it to the
//! request flags the medium is handed.
//!
//! The interesting assertion is not that the hint is stored. It is that a page
//! of the hinted file's data arrives at the MEDIUM carrying the flag, and that
//! a page of anything else's does not — a hint the write path never reads is
//! indistinguishable from no hint at all, and reads exactly the same back.

use alloc::vec;
use alloc::vec::Vec;

use sectors::{MemImage, SectorSource};
use syscall::errno::Errno;

use crate::ioctl::entry::{handle, Answer};
use crate::ioctl::perm::Ctx;
use crate::ioctl::req::Extra;
use crate::ioctl::uapi::{IOPRIO_MAX, IOPRIO_WRITE, IO_PRIO};
use crate::mode::{S_IFDIR, S_IFREG};
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::ioprio::{data_flags, valid_level, IOPRIO_NONE};
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 3);
const BLK: u64 = BLKSIZE as u64;

fn spec(mode: u16) -> NewInode { NewInode { mode, uid: 0, gid: 0, rdev: 0, now: NOW } }

/// A medium that records the flags of every write, and writes the bytes.
///
/// Wrapping the real image rather than replacing it, so a test that asserts on
/// flags is running the same write path a test that asserts on bytes does.
struct Recorder {
    inner: MemImage,
    seen: core::cell::RefCell<Vec<(u64, block::RequestFlags)>>,
}

impl Recorder {
    fn new(inner: MemImage) -> Self { Self { inner, seen: core::cell::RefCell::new(Vec::new()) } }
    fn take(&self) -> Vec<(u64, block::RequestFlags)> { core::mem::take(&mut self.seen.borrow_mut()) }
}

impl SectorSource for Recorder {
    fn read_sectors(&self, sector: u64, buf: &mut [u8]) -> Result<(), Errno> {
        self.inner.read_sectors(sector, buf)
    }
    fn write_sectors(&self, sector: u64, buf: &[u8]) -> Result<(), Errno> {
        self.write_sectors_flags(sector, buf, block::RequestFlags::NONE)
    }
    fn write_sectors_flags(&self, sector: u64, buf: &[u8], flags: block::RequestFlags)
        -> Result<(), Errno> {
        self.seen.borrow_mut().push((sector, flags));
        self.inner.write_sectors(sector, buf)
    }
    fn writable(&self) -> bool { self.inner.writable() }
}

/// A writable volume over a recording medium, holding one empty regular file.
fn recorded() -> (Volume<Recorder>, u32) {
    let bytes = test_image::with_root().finish();
    let src = Recorder::new(MemImage::from_bytes(BLKSIZE as u32, bytes));
    let mut v = Volume::mount_with(src, Options::defaults(), true).unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(S_IFREG | 0o644), None).unwrap();
    (v, ino)
}

/// The addresses written with the urgency boost, and those written without it.
fn split(seen: &[(u64, block::RequestFlags)]) -> (Vec<u64>, Vec<u64>) {
    let boosted = seen.iter().filter(|(_, f)| f.contains(block::flags::PRIO)).map(|(a, _)| *a).collect();
    let plain = seen.iter().filter(|(_, f)| !f.contains(block::flags::PRIO)).map(|(a, _)| *a).collect();
    (boosted, plain)
}

fn root() -> Ctx {
    Ctx {
        cap_sys_admin: true, fmode_read: true, fmode_write: true, o_direct: false,
        owner_or_capable: true, mnt_writable: true, writecount: 1, dirty_pages: 0,
        mmapped: false, dst: crate::ioctl::DstFd::Unusable,
    }
}

// ------------------------------------------------------------------- the hint

#[test]
fn a_file_starts_with_no_hint() {
    let (v, ino) = recorded();
    assert_eq!(v.io_prio(ino), IOPRIO_NONE);
}

#[test]
fn a_hint_reads_back_and_clearing_it_removes_it() {
    let (mut v, ino) = recorded();
    v.set_io_prio(ino, IOPRIO_WRITE).unwrap();
    assert_eq!(v.io_prio(ino), IOPRIO_WRITE);
    v.set_io_prio(ino, IOPRIO_NONE).unwrap();
    assert_eq!(v.io_prio(ino), IOPRIO_NONE);
    // Cleared means GONE, not stored as zero: the map holds hints, not files.
    assert!(v.ioprio_hint.is_empty());
}

#[test]
fn a_level_the_build_does_not_know_is_refused_rather_than_stored() {
    let (mut v, ino) = recorded();
    assert_eq!(v.set_io_prio(ino, IOPRIO_MAX), Err(Errno::Einval));
    assert_eq!(v.set_io_prio(ino, u32::MAX), Err(Errno::Einval));
    assert_eq!(v.io_prio(ino), IOPRIO_NONE);
    assert!(valid_level(IOPRIO_NONE) && valid_level(IOPRIO_WRITE));
    assert!(!valid_level(IOPRIO_MAX));
}

#[test]
fn only_the_write_hint_produces_a_flag() {
    assert_eq!(data_flags(IOPRIO_NONE), block::RequestFlags::NONE);
    assert_eq!(data_flags(IOPRIO_WRITE), block::flags::PRIO);
    // An unrecognised level is not silently treated as the boost.
    assert_eq!(data_flags(IOPRIO_MAX), block::RequestFlags::NONE);
}

#[test]
fn a_hint_does_not_outlive_the_inode_it_was_set_on() {
    // The number is reused. A hint left behind would boost whichever file
    // takes it next, which is a file nobody asked to boost.
    let (mut v, ino) = recorded();
    v.set_io_prio(ino, IOPRIO_WRITE).unwrap();
    v.remove(ROOT_INO, b"f", false, NOW).unwrap();
    assert_eq!(v.io_prio(ino), IOPRIO_NONE);
}

// ------------------------------------------------- the flag reaching the medium

#[test]
fn a_hinted_files_data_page_reaches_the_medium_boosted() {
    let (mut v, ino) = recorded();
    v.set_io_prio(ino, IOPRIO_WRITE).unwrap();
    v.source_ref().take();
    v.write_file(ino, 0, &vec![0xA1u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    let seen = v.source_ref().take();
    let (boosted, _) = split(&seen);
    // Exactly one boosted write: the page itself. The node blocks around it
    // are metadata and are not the file's data.
    assert_eq!(boosted.len(), 1, "seen: {seen:?}");
    assert_eq!(u64::from(v.mapped_addr(ino, 0).unwrap().unwrap()), boosted[0]);
}

#[test]
fn an_unhinted_files_data_page_reaches_the_medium_plain() {
    // The positive control for the test above: the same write, same path,
    // same assertions, with the hint the only difference.
    let (mut v, ino) = recorded();
    v.source_ref().take();
    v.write_file(ino, 0, &vec![0xA1u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    let seen = v.source_ref().take();
    let (boosted, plain) = split(&seen);
    assert!(boosted.is_empty(), "seen: {seen:?}");
    assert!(plain.contains(&u64::from(v.mapped_addr(ino, 0).unwrap().unwrap())));
}

#[test]
fn clearing_the_hint_stops_the_boost() {
    let (mut v, ino) = recorded();
    v.set_io_prio(ino, IOPRIO_WRITE).unwrap();
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    assert!(!split(&v.source_ref().take()).0.is_empty());
    v.set_io_prio(ino, IOPRIO_NONE).unwrap();
    v.write_file(ino, BLK, &vec![2u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    assert!(split(&v.source_ref().take()).0.is_empty());
}

#[test]
fn one_files_hint_does_not_boost_another_files_writes() {
    let (mut v, hinted) = recorded();
    let other = v.create(ROOT_INO, b"g", &spec(S_IFREG | 0o644), None).unwrap();
    v.set_io_prio(hinted, IOPRIO_WRITE).unwrap();
    v.source_ref().take();
    v.write_file(other, 0, &vec![7u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    assert!(split(&v.source_ref().take()).0.is_empty());
}

// ------------------------------------------------------------------- metadata

#[test]
fn metadata_writes_are_marked_as_metadata() {
    let (mut v, ino) = recorded();
    v.write_file(ino, 0, &vec![3u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    v.source_ref().take();
    v.commit().unwrap();
    let seen = v.source_ref().take();
    assert!(!seen.is_empty());
    // A checkpoint writes nothing but metadata, so every write it makes says
    // so. One unmarked write here means a metadata writer the classification
    // does not reach.
    let unmarked: Vec<u64> = seen.iter().filter(|(_, f)| !f.contains(block::flags::META))
                                 .map(|(a, _)| *a).collect();
    assert!(unmarked.is_empty(), "unmarked metadata writes at {unmarked:?}");
}

#[test]
fn a_data_page_is_not_marked_as_metadata() {
    // The positive control for the test above: if everything were marked, the
    // assertion there would pass for the wrong reason.
    let (mut v, ino) = recorded();
    v.source_ref().take();
    v.write_file(ino, 0, &vec![4u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    let seen = v.source_ref().take();
    let data = u64::from(v.mapped_addr(ino, 0).unwrap().unwrap());
    let flags = seen.iter().find(|(a, _)| *a == data).expect("the data page was written").1;
    assert!(!flags.contains(block::flags::META));
    // And the node blocks written alongside it ARE marked, so the two are
    // being told apart rather than all landing on one answer.
    assert!(seen.iter().any(|(a, f)| *a != data && f.contains(block::flags::META)), "seen: {seen:?}");
}

// ---------------------------------------------------------------------- ioctl

#[test]
fn the_ioctl_sets_the_hint_the_write_path_reads() {
    let (mut v, ino) = recorded();
    let a = handle(&mut v, ino, IO_PRIO, &IOPRIO_WRITE.to_le_bytes(), &Extra::default(), &root());
    assert!(matches!(a, Ok(Answer::Done(_))), "{a:?}");
    assert_eq!(v.io_prio(ino), IOPRIO_WRITE);
    v.source_ref().take();
    v.write_file(ino, 0, &vec![5u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    assert_eq!(split(&v.source_ref().take()).0.len(), 1);
}

#[test]
fn the_ioctl_refuses_a_level_at_or_past_the_maximum() {
    let (mut v, ino) = recorded();
    assert_eq!(handle(&mut v, ino, IO_PRIO, &IOPRIO_MAX.to_le_bytes(), &Extra::default(), &root())
                   .err(), Some(Errno::Einval));
    assert_eq!(v.io_prio(ino), IOPRIO_NONE);
}

#[test]
fn the_ioctl_refuses_anything_that_is_not_a_regular_file() {
    let (mut v, _) = recorded();
    let dir = v.create(ROOT_INO, b"d", &spec(S_IFDIR | 0o755), None).unwrap();
    assert_eq!(handle(&mut v, dir, IO_PRIO, &IOPRIO_WRITE.to_le_bytes(), &Extra::default(), &root())
                   .err(), Some(Errno::Einval));
    assert_eq!(v.io_prio(dir), IOPRIO_NONE);
}
