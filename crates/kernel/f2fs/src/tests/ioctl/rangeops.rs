//! The three range commands, driven by their real numbers.
//!
//! Each one's volume operation has its own tests; these are the ones those
//! cannot replace. A command wired to the wrong operation, handed the wrong
//! argument, or answered through the wrong channel passes every unit test of
//! the operation and fails here — and the destination a move names is resolved
//! outside this crate, so the rung its two failure modes are refused at is
//! only observable through the whole path.

use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;
use syscall::errno::Errno;

use crate::ioctl::entry::{handle, Answer};
use crate::ioctl::perm::Ctx;
use crate::ioctl::req::Extra;
use crate::ioctl::uapi::*;
use crate::ioctl::DstFd;
use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 15);
const BLK: u64 = BLKSIZE as u64;

fn root() -> Ctx {
    Ctx {
        cap_sys_admin: true, fmode_read: true, fmode_write: true, o_direct: false,
        owner_or_capable: true, mnt_writable: true, writecount: 1, dirty_pages: 0,
        mmapped: false, dst: DstFd::Unusable,
    }
}

fn send(v: &mut Volume<MemImage>, ino: u32, cmd: u32, p: &[u8], c: &Ctx)
    -> Result<Answer, Errno> {
    handle(v, ino, cmd, p, &Extra::default(), c)
}

fn payload_of(a: &Answer) -> Vec<u8> {
    match a {
        Answer::Done(r) => r.payload.clone().expect("a payload"),
        Answer::NotBuilt(u) => panic!("not built: {u:?}"),
    }
}

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

/// A block whose every byte names it, so a block in the wrong place says where
/// it came from. # C: O(BLKSIZE)
fn page(tag: u8) -> Vec<u8> { vec![tag; BLKSIZE] }

/// # C: O(image)
fn remount(mut v: Volume<MemImage>) -> Volume<MemImage> {
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

/// One byte per block, read back through the ordinary reader.
/// # C: O(file bytes)
fn tags(v: &Volume<MemImage>, ino: u32, n: u64) -> Vec<u8> {
    let inode = v.read_inode(ino).unwrap();
    let mut out = vec![0u8; (n * BLK) as usize];
    v.read_file(&inode, ino, 0, &mut out).unwrap();
    (0..n).map(|i| out[(i * BLK) as usize]).collect()
}

fn addrs(v: &Volume<MemImage>, ino: u32, n: u64) -> Vec<u32> {
    (0..n).map(|i| v.mapped_addr(ino, i).unwrap().unwrap()).collect()
}

/// Three blocks written OUT OF ORDER, so the file's logical order and its
/// physical order are unrelated. # C: O(1 image)
fn scattered() -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    for index in [2u64, 0, 1] {
        v.write_file(ino, index * BLK, &page(index as u8 + 1)).unwrap();
    }
    // A checkpoint first: the rewrite's gate asks whether there is room for
    // the old blocks AND the new ones at once.
    v.commit().unwrap();
    (v, ino)
}

fn defrag_payload(start: u64, len: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(DEFRAGMENT_SIZE as usize);
    b.extend_from_slice(&start.to_le_bytes());
    b.extend_from_slice(&len.to_le_bytes());
    b
}

fn move_payload(dst_fd: u32, pos_in: u64, pos_out: u64, len: u64) -> Vec<u8> {
    let mut b = vec![0u8; MOVE_RANGE_SIZE as usize];
    b[0..4].copy_from_slice(&dst_fd.to_le_bytes());
    b[8..16].copy_from_slice(&pos_in.to_le_bytes());
    b[16..24].copy_from_slice(&pos_out.to_le_bytes());
    b[24..32].copy_from_slice(&len.to_le_bytes());
    b
}

fn trim_payload(start: u64, len: u64, flags: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(SECTRIM_RANGE_SIZE as usize);
    b.extend_from_slice(&start.to_le_bytes());
    b.extend_from_slice(&len.to_le_bytes());
    b.extend_from_slice(&flags.to_le_bytes());
    b
}

// ---- defragment -----------------------------------------------------------

#[test]
fn the_defragment_command_makes_the_range_one_run() {
    let (mut v, ino) = scattered();
    let before = addrs(&v, ino, 3);
    assert!(before.windows(2).any(|w| w[1] != w[0] + 1), "already one run: {before:?}");
    send(&mut v, ino, DEFRAGMENT, &defrag_payload(0, 3 * BLK), &root()).unwrap();
    let v = remount(v);
    let after = addrs(&v, ino, 3);
    assert!(after.windows(2).all(|w| w[1] == w[0] + 1), "not one run: {after:?}");
    assert_eq!(tags(&v, ino, 3), vec![1, 2, 3], "the bytes moved with the blocks");
}

#[test]
fn the_defragment_command_reports_the_bytes_it_moved_in_the_callers_argument() {
    // The caller's `start` comes back untouched and its `len` is replaced by
    // what actually moved: that difference is how a caller tells a range that
    // was already contiguous from one this had to rewrite.
    let (mut v, ino) = scattered();
    let a = send(&mut v, ino, DEFRAGMENT, &defrag_payload(0, 3 * BLK), &root()).unwrap();
    let out = payload_of(&a);
    assert_eq!(out.len(), DEFRAGMENT_SIZE as usize);
    assert_eq!(u64::from_le_bytes(out[0..8].try_into().unwrap()), 0, "start was rewritten");
    let moved = u64::from_le_bytes(out[8..16].try_into().unwrap());
    assert!(moved > 0 && moved <= 3 * BLK, "moved {moved}");

    // A second pass has nothing left to do, and says so.
    let a = send(&mut v, ino, DEFRAGMENT, &defrag_payload(0, 3 * BLK), &root()).unwrap();
    let out = payload_of(&a);
    assert_eq!(u64::from_le_bytes(out[8..16].try_into().unwrap()), 0,
               "a range that is already one run moved nothing");
}

// ---- move range -----------------------------------------------------------

/// Two files on one volume, and the destination's inode number.
/// # C: O(1 image)
fn two_files() -> (Volume<MemImage>, u32, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let src = v.create(ROOT_INO, b"src", &spec(), None).unwrap();
    let dst = v.create(ROOT_INO, b"dst", &spec(), None).unwrap();
    for i in 0..2u64 { v.write_file(src, i * BLK, &page(i as u8 + 1)).unwrap(); }
    v.write_file(dst, 0, &page(9)).unwrap();
    v.commit().unwrap();
    (v, src, dst)
}

#[test]
fn the_move_command_hands_the_blocks_to_the_file_the_descriptor_named() {
    let (mut v, src, dst) = two_files();
    let c = Ctx { dst: DstFd::Ours(dst), ..root() };
    send(&mut v, src, MOVE_RANGE, &move_payload(3, 0, BLK, 2 * BLK), &c).unwrap();
    let v = remount(v);
    // The destination keeps its own first block and gains the source's two.
    assert_eq!(tags(&v, dst, 3), vec![9, 1, 2]);
    // And the source no longer holds them: a MOVE, not a copy.
    let inode = v.read_inode(src).unwrap();
    assert!(v.stored_addr(&inode, src, 0).unwrap() == crate::uapi::NULL_ADDR,
            "the source kept the block it handed over");
}

#[test]
fn a_destination_that_cannot_be_written_is_a_bad_descriptor() {
    let (mut v, src, _) = two_files();
    assert_eq!(send(&mut v, src, MOVE_RANGE, &move_payload(3, 0, 0, BLK), &root()).map(|_| ()),
               Err(Errno::Ebadf));
}

#[test]
fn a_destination_on_another_volume_is_refused_as_a_cross_device_move() {
    let (mut v, src, _) = two_files();
    let c = Ctx { dst: DstFd::Foreign, ..root() };
    assert_eq!(send(&mut v, src, MOVE_RANGE, &move_payload(3, 0, 0, BLK), &c).map(|_| ()),
               Err(Errno::Exdev));
}

#[test]
fn the_move_command_writes_nothing_back_to_the_caller() {
    // Its number encodes both directions and the interface defines no reply.
    // A layer copying by the encoded direction would hand the caller bytes
    // Linux never writes.
    assert!(crate::ioctl::spec::reads_payload(MOVE_RANGE));
    assert!(!crate::ioctl::spec::writes_payload(MOVE_RANGE));
    let (mut v, src, dst) = two_files();
    let c = Ctx { dst: DstFd::Ours(dst), ..root() };
    let a = send(&mut v, src, MOVE_RANGE, &move_payload(3, 0, 0, BLK), &c).unwrap();
    match a {
        Answer::Done(r) => assert!(r.payload.is_none(), "the move wrote bytes back"),
        Answer::NotBuilt(u) => panic!("not built: {u:?}"),
    }
}

// ---- secure trim ----------------------------------------------------------

#[test]
fn the_trim_command_destroys_the_bytes_and_keeps_the_file() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    for i in 0..3u64 { v.write_file(ino, i * BLK, &page(i as u8 + 1)).unwrap(); }
    let before = v.read_inode(ino).unwrap();
    let held = addrs(&v, ino, 3);
    send(&mut v, ino, SEC_TRIM_FILE, &trim_payload(BLK, BLK, TRIM_FILE_ZEROOUT), &root())
        .unwrap();
    let v = remount(v);
    let after = v.read_inode(ino).unwrap();
    assert_eq!(after.size, before.size, "the length changed");
    assert_eq!(after.blocks, before.blocks, "a block was given up");
    assert_eq!(addrs(&v, ino, 3), held, "an address moved");
    assert_eq!(tags(&v, ino, 3), vec![1, 0, 3], "the wrong blocks were erased");
}

#[test]
fn a_trim_that_names_nothing_is_a_success_that_erases_nothing() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &page(1)).unwrap();
    send(&mut v, ino, SEC_TRIM_FILE, &trim_payload(0, 0, TRIM_FILE_ZEROOUT), &root()).unwrap();
    assert_eq!(tags(&v, ino, 1), vec![1]);
}

/// The span arithmetic the ladder applies is the trim's OWN, so the ladder
/// admits exactly what the trim can carry out.
///
/// The case that shows it is the tail. A request reaching the end of the file
/// may end mid-block, because the file itself does — its last block is on the
/// medium whole and erasing it whole destroys only bytes past the length. A
/// ladder carrying its own copy of the rule tends to demand the end be
/// aligned like any other, and then refuses a request the trim would have
/// carried out — a refusal no test of the trim can see, because the trim is
/// never reached.
#[test]
fn a_request_that_ends_at_a_ragged_end_of_file_is_admitted() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    for i in 0..3u64 { v.write_file(ino, i * BLK, &page(i as u8 + 1)).unwrap(); }
    // Seven bytes into a fourth block: the file's own end is not aligned.
    v.write_file(ino, 3 * BLK, &[4u8; 7]).unwrap();
    let size = v.read_inode(ino).unwrap().size;
    assert_ne!(size % BLK, 0, "the fixture's end is aligned, so the case proves nothing");

    let p = trim_payload(BLK, size - BLK, TRIM_FILE_ZEROOUT);
    send(&mut v, ino, SEC_TRIM_FILE, &p, &root()).unwrap();
    let v = remount(v);
    assert_eq!(tags(&v, ino, 4), vec![1, 0, 0, 0], "the tail was not erased");
}

/// And a request that stops SHORT of the end may not end mid-block: erasing
/// the rest of a block whose front the caller wants to keep would destroy
/// bytes nobody asked about.
#[test]
fn a_request_that_stops_short_of_the_end_must_end_on_a_block() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    for i in 0..3u64 { v.write_file(ino, i * BLK, &page(i as u8 + 1)).unwrap(); }
    let size = v.read_inode(ino).unwrap().size;
    for (start, len) in [(BLK + 1, BLK), (BLK, BLK + 1), (size, BLK)] {
        let p = trim_payload(start, len, TRIM_FILE_ZEROOUT);
        assert_eq!(send(&mut v, ino, SEC_TRIM_FILE, &p, &root()).map(|_| ()),
                   Err(Errno::Einval), "start {start} len {len}");
    }
    assert_eq!(tags(&v, ino, 3), vec![1, 2, 3], "a refused request erased something");
}
