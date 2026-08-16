//! The atomic-write span, driven by its real command numbers.
//!
//! Every case checks the RESULT through a different path than the one the
//! command took — the file's own reader, the volume's span table, a remount —
//! so a command wired to the wrong operation cannot pass by agreeing with
//! itself. Before this the four numbers were admitted and answered nothing.

use sectors::MemImage;
use syscall::errno::Errno;

use crate::ioctl::entry::{handle, Answer};
use crate::ioctl::perm::Ctx;
use crate::ioctl::req::Extra;
use crate::ioctl::uapi::*;
use crate::mode::S_IFREG;
use crate::test_image::{self, ROOT_INO};
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 3);

fn root() -> Ctx {
    Ctx {
        cap_sys_admin: true, fmode_read: true, fmode_write: true, o_direct: false,
        owner_or_capable: true, mnt_writable: true, writecount: 1, dirty_pages: 0,
        mmapped: false, dst: crate::ioctl::DstFd::Unusable,
    }
}

fn send(v: &mut Volume<MemImage>, ino: u32, cmd: u32) -> Result<Answer, Errno> {
    handle(v, ino, cmd, &[], &Extra::default(), &root())
}

/// A writable volume holding one file of `bytes`. # C: O(1 image)
fn one_file(bytes: &[u8]) -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f",
                       &NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW },
                       None).unwrap();
    if !bytes.is_empty() { v.write_file(ino, 0, bytes).unwrap(); }
    (v, ino)
}

/// The file's bytes as an ordinary reader sees them. # C: O(file bytes)
fn whole(v: &Volume<MemImage>, ino: u32) -> alloc::vec::Vec<u8> {
    let inode = v.read_inode(ino).unwrap();
    v.read_whole(&inode, ino).unwrap()
}

#[test]
fn starting_a_span_through_the_command_opens_one_on_the_volume() {
    let (mut v, ino) = one_file(b"before");
    assert!(!v.is_atomic_file(ino));
    send(&mut v, ino, START_ATOMIC_WRITE).unwrap();
    assert!(v.is_atomic_file(ino), "the command did not reach the volume");
    assert!(v.atomic_cow_ino(ino).is_some(), "a span with no shadow inode holds nothing");
}

#[test]
fn a_second_start_on_an_open_span_is_the_same_span() {
    // A no-op rather than a refusal: a caller that starts twice is asking for
    // the state it is already in, and a fresh shadow inode would strand the
    // blocks the first span had already collected.
    let (mut v, ino) = one_file(b"before");
    send(&mut v, ino, START_ATOMIC_WRITE).unwrap();
    let cow = v.atomic_cow_ino(ino).unwrap();
    send(&mut v, ino, START_ATOMIC_WRITE).unwrap();
    assert_eq!(v.atomic_cow_ino(ino), Some(cow));
}

/// The block the file's own index holds for `index`, which is what a reader
/// that knows nothing of the span would follow. # C: O(1 block)
fn file_addr(v: &Volume<MemImage>, ino: u32, index: u64) -> u32 {
    let inode = v.read_inode(ino).unwrap();
    v.stored_addr(&inode, ino, index).unwrap()
}

#[test]
fn nothing_the_span_wrote_reaches_the_file_until_the_commit_command() {
    let (mut v, ino) = one_file(b"before");
    send(&mut v, ino, START_ATOMIC_WRITE).unwrap();
    // Read after the start: opening a span moves inline data out to a block,
    // which is part of opening one rather than part of writing to it.
    let was = file_addr(&v, ino, 0);
    v.atomic_write_file(ino, 0, b"after!").unwrap();
    // The file's own index is untouched: the block the span wrote belongs to
    // the shadow inode until the commit moves it across.
    assert_eq!(file_addr(&v, ino, 0), was, "the span reached the file before its commit");
    send(&mut v, ino, COMMIT_ATOMIC_WRITE).unwrap();
    assert_ne!(file_addr(&v, ino, 0), was, "the commit moved nothing");
    assert!(!v.is_atomic_file(ino), "the span outlived its commit");
    assert_eq!(whole(&v, ino), b"after!");
}

#[test]
fn a_committed_span_survives_a_remount() {
    let (mut v, ino) = one_file(b"before");
    send(&mut v, ino, START_ATOMIC_WRITE).unwrap();
    v.atomic_write_file(ino, 0, b"after!").unwrap();
    send(&mut v, ino, COMMIT_ATOMIC_WRITE).unwrap();
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    let v = Volume::mount_with(MemImage::from_bytes(crate::uapi::BLKSIZE as u32, bytes),
                               crate::opts::Options::defaults(), true).unwrap();
    assert_eq!(whole(&v, ino), b"after!");
}

#[test]
fn the_abort_command_leaves_the_file_exactly_as_it_was() {
    let (mut v, ino) = one_file(b"before");
    send(&mut v, ino, START_ATOMIC_WRITE).unwrap();
    v.atomic_write_file(ino, 0, b"after!").unwrap();
    send(&mut v, ino, ABORT_ATOMIC_WRITE).unwrap();
    assert!(!v.is_atomic_file(ino));
    assert_eq!(whole(&v, ino), b"before");
}

#[test]
fn aborting_a_file_with_no_span_open_succeeds() {
    // A cleanup path must not have to know whether its own earlier start got
    // as far as opening one.
    let (mut v, ino) = one_file(b"before");
    send(&mut v, ino, ABORT_ATOMIC_WRITE).unwrap();
    assert_eq!(whole(&v, ino), b"before");
}

#[test]
fn a_replacing_span_discards_everything_it_did_not_write() {
    let (mut v, ino) = one_file(&[7u8; 3 * crate::uapi::BLKSIZE]);
    send(&mut v, ino, START_ATOMIC_REPLACE).unwrap();
    // The file reads as empty to the writer from the moment the span opens.
    assert_eq!(v.read_inode(ino).unwrap().size, 0);
    v.atomic_write_file(ino, 0, b"short").unwrap();
    send(&mut v, ino, COMMIT_ATOMIC_WRITE).unwrap();
    assert_eq!(whole(&v, ino), b"short");
}

#[test]
fn an_ordinary_span_keeps_the_bytes_it_did_not_write() {
    let (mut v, ino) = one_file(b"0123456789");
    send(&mut v, ino, START_ATOMIC_WRITE).unwrap();
    v.atomic_write_file(ino, 4, b"XX").unwrap();
    send(&mut v, ino, COMMIT_ATOMIC_WRITE).unwrap();
    assert_eq!(whole(&v, ino), b"0123XX6789");
}

#[test]
fn a_directory_may_not_open_a_span() {
    let (mut v, _) = one_file(b"");
    assert_eq!(send(&mut v, ROOT_INO, START_ATOMIC_WRITE).map(|_| ()), Err(Errno::Einval));
}

#[test]
fn a_pinned_file_may_not_open_a_span() {
    // A commit is nothing but a move, and a pin is the promise that the file's
    // blocks do not move.
    let (mut v, ino) = one_file(b"");
    v.set_pinned(ino, true).unwrap();
    assert_eq!(send(&mut v, ino, START_ATOMIC_WRITE).map(|_| ()), Err(Errno::Einval));
}

#[test]
fn a_read_only_mount_refuses_all_three() {
    let (mut v, ino) = one_file(b"before");
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    let mut v = Volume::mount_with(MemImage::from_bytes(crate::uapi::BLKSIZE as u32, bytes),
                                   crate::opts::Options::defaults(), false).unwrap();
    let c = Ctx { mnt_writable: false, ..root() };
    for cmd in [START_ATOMIC_WRITE, START_ATOMIC_REPLACE, COMMIT_ATOMIC_WRITE,
                ABORT_ATOMIC_WRITE] {
        assert_eq!(handle(&mut v, ino, cmd, &[], &Extra::default(), &c).map(|_| ()),
                   Err(Errno::Erofs), "{cmd:#x}");
    }
}
