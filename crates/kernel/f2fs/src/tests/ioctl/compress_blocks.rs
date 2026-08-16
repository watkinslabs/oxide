//! Handing the saving back and taking it again, through the real commands.
//!
//! The three counts a release moves — the volume's, the file's blocks and the
//! file's saving — are checked against EACH OTHER and against the segment
//! table, not against the value the release happened to return. A release that
//! agreed with itself and with nothing else is exactly the defect: the space
//! either never comes back or comes back twice, and neither shows up until a
//! checker reads the volume.

use alloc::vec::Vec;
use sectors::MemImage;
use syscall::errno::Errno;

use crate::compress::algo::COMPRESS_LZ4;
use crate::ioctl::entry::{handle, Answer};
use crate::ioctl::perm::Ctx;
use crate::ioctl::req::Extra;
use crate::ioctl::uapi::*;
use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::{le32, BLKSIZE, COMPRESS_ADDR, I_COMPRESS_ALGORITHM, I_COMPRESS_FLAG, I_FLAGS,
                  I_LOG_CLUSTER_SIZE, NEW_ADDR};
use crate::volume::dnode::{put16, put32};
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 9);
/// Four blocks per cluster, which is the width every case here is stated in.
const LOG_CS: u8 = 2;
const CS: usize = 1 << LOG_CS;

fn root() -> Ctx {
    Ctx {
        cap_sys_admin: true, fmode_read: true, fmode_write: true, o_direct: false,
        owner_or_capable: true, mnt_writable: true, writecount: 1, dirty_pages: 0,
        mmapped: false, dst: crate::ioctl::DstFd::Unusable,
    }
}

fn send(v: &mut Volume<MemImage>, ino: u32, cmd: u32) -> Result<Answer, Errno> {
    handle(v, ino, cmd, &[0u8; 8], &Extra::default(), &root())
}

/// The count a command reported through the caller's argument. # C: O(1)
fn count(a: Answer) -> u64 {
    let Answer::Done(r) = a else { panic!("not built") };
    let p = r.payload.expect("a payload");
    u64::from_le_bytes(p[..8].try_into().unwrap())
}

/// Bytes that compress well. # C: O(n)
fn patterned(n: usize) -> Vec<u8> { (0..n).map(|i| ((i / 64) % 11) as u8).collect() }

/// A volume with one compressed file of `clusters` full clusters written.
/// # C: O(1 image)
fn with_compressed(clusters: usize) -> (Volume<MemImage>, u32) {
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_COMPRESSION;
    let mut v = b.mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"c",
                       &NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW },
                       None).unwrap();
    v.stamp_inode(ino, |b| {
        let f = le32(b, I_FLAGS).unwrap_or(0) | crate::flags::F2FS_COMPR_FL;
        put32(b, I_FLAGS, f);
        b[I_COMPRESS_ALGORITHM] = COMPRESS_LZ4;
        b[I_LOG_CLUSTER_SIZE] = LOG_CS;
        put16(b, I_COMPRESS_FLAG, 0);
    })
    .unwrap();
    v.write_compressed(ino, 0, &patterned(clusters * CS * BLKSIZE)).unwrap();
    (v, ino)
}

/// # C: O(image)
fn remount(mut v: Volume<MemImage>) -> Volume<MemImage> {
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

/// How far the volume's block count runs ahead of the segment table, which is
/// the number of MARKS outstanding — a mark occupies a slot and names no
/// block, so it is counted by the volume and not by the table.
/// # C: O(main segments)
fn drift(v: &mut Volume<MemImage>) -> i64 {
    v.load_segments().unwrap();
    let live: i64 = (0..v.sb.segment_count_main).map(|s| i64::from(v.seg_valid(s))).sum();
    v.valid_block_count as i64 - live
}

/// One cluster's stored addresses. # C: O(cluster blocks)
fn addrs(v: &Volume<MemImage>, ino: u32, first: u64) -> Vec<u32> {
    let inode = v.read_inode(ino).unwrap();
    let g = v.geometry(&inode).unwrap();
    v.cluster_addrs(&inode, ino, &g, first).unwrap()
}

#[test]
fn releasing_hands_back_exactly_the_saving_the_inode_recorded() {
    let (mut v, ino) = with_compressed(2);
    let saved = v.compr_blocks(ino).unwrap();
    assert!(saved > 0, "nothing was saved, so the case proves nothing");
    let blocks = v.read_inode(ino).unwrap().blocks;
    let n = count(send(&mut v, ino, RELEASE_COMPRESS_BLOCKS).unwrap());
    assert_eq!(n, saved, "the count handed back is the saving that was recorded");
    let after = v.read_inode(ino).unwrap();
    assert_eq!(after.compr_blocks, 0, "a released file has no saving left to give");
    assert_eq!(after.blocks, blocks - saved, "the file's own count did not follow");
}

#[test]
fn the_volume_gets_the_blocks_back_and_a_remount_agrees() {
    let (mut v, ino) = with_compressed(2);
    let empty = {
        // The drift of a volume holding no marks at all, which is what a full
        // release must return this one to.
        let mut clean = test_image::with_root().mount_rw().unwrap();
        drift(&mut clean)
    };
    assert!(drift(&mut v) > empty, "the file holds no marks, so the case proves nothing");
    let n = count(send(&mut v, ino, RELEASE_COMPRESS_BLOCKS).unwrap());
    assert!(n > 0);
    assert_eq!(drift(&mut v), empty, "the volume kept the charge for a released slot");
    let mut v = remount(v);
    assert_eq!(drift(&mut v), empty, "the release did not survive the remount");
    assert_eq!(v.read_inode(ino).unwrap().compr_blocks, 0);
}

#[test]
fn a_released_cluster_keeps_its_sentinel_and_its_image() {
    // The slot is what says the cluster is an image at all; clearing it would
    // leave the blocks after it unreadable, and the file's bytes must survive
    // a release untouched.
    let (mut v, ino) = with_compressed(1);
    let want = patterned(CS * BLKSIZE);
    send(&mut v, ino, RELEASE_COMPRESS_BLOCKS).unwrap();
    let a = addrs(&v, ino, 0);
    assert_eq!(a[0], COMPRESS_ADDR, "{a:?}");
    assert!(!a[1..].iter().any(|&x| x == NEW_ADDR), "a reservation outlived the release: {a:?}");
    let v = remount(v);
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(v.read_whole(&inode, ino).unwrap(), want);
}

#[test]
fn reserving_puts_back_exactly_what_the_release_took() {
    let (mut v, ino) = with_compressed(2);
    let before = v.read_inode(ino).unwrap();
    let (blocks, saved) = (before.blocks, before.compr_blocks);
    let base = drift(&mut v);
    let released = count(send(&mut v, ino, RELEASE_COMPRESS_BLOCKS).unwrap());
    // Across a remount, so the reserve works from the medium's own state
    // rather than from anything this mount remembers.
    let mut v = remount(v);
    let taken = count(send(&mut v, ino, RESERVE_COMPRESS_BLOCKS).unwrap());
    assert_eq!(taken, released, "what came back is not what was taken");
    let after = v.read_inode(ino).unwrap();
    assert_eq!(after.blocks, blocks);
    assert_eq!(after.compr_blocks, saved);
    assert_eq!(drift(&mut v), base, "the volume's own count did not come back");
    let v = remount(v);
    assert_eq!(v.read_inode(ino).unwrap().compr_blocks, saved);
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(v.read_whole(&inode, ino).unwrap(), patterned(2 * CS * BLKSIZE));
}

#[test]
fn a_file_that_saved_nothing_is_refused_rather_than_marked_released() {
    // Marking it would make it unwritable and hand back nothing, which is a
    // worse state than the one the caller asked to leave.
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_COMPRESSION;
    let mut v = b.mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"c",
                       &NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW },
                       None).unwrap();
    v.stamp_inode(ino, |b| {
        let f = le32(b, I_FLAGS).unwrap_or(0) | crate::flags::F2FS_COMPR_FL;
        put32(b, I_FLAGS, f);
        b[I_COMPRESS_ALGORITHM] = COMPRESS_LZ4;
        b[I_LOG_CLUSTER_SIZE] = LOG_CS;
    })
    .unwrap();
    assert_eq!(send(&mut v, ino, RELEASE_COMPRESS_BLOCKS).map(|_| ()), Err(Errno::Eperm));
    assert!(!v.read_inode(ino).unwrap().has(crate::flags::COMPRESS_RELEASED));
}

#[test]
fn releasing_twice_is_refused() {
    let (mut v, ino) = with_compressed(1);
    send(&mut v, ino, RELEASE_COMPRESS_BLOCKS).unwrap();
    assert_eq!(send(&mut v, ino, RELEASE_COMPRESS_BLOCKS).map(|_| ()), Err(Errno::Einval));
}

#[test]
fn reserving_a_file_that_was_never_released_is_refused() {
    let (mut v, ino) = with_compressed(1);
    assert_eq!(send(&mut v, ino, RESERVE_COMPRESS_BLOCKS).map(|_| ()), Err(Errno::Einval));
}

#[test]
fn a_second_writer_stops_a_release() {
    // Past the release the file cannot be written, so a description that could
    // still write it would be holding a promise the release breaks.
    let (mut v, ino) = with_compressed(1);
    let c = Ctx { writecount: 2, ..root() };
    assert_eq!(handle(&mut v, ino, RELEASE_COMPRESS_BLOCKS, &[0u8; 8], &Extra::default(), &c)
                   .map(|_| ()),
               Err(Errno::Ebusy));
}

#[test]
fn truncating_a_released_file_away_gives_nothing_back_twice() {
    // The sentinel of a released cluster is still IN the slot and no longer
    // charged. A truncation that treated it like any other mark would hand its
    // charge back a second time, and the volume would report free space that
    // does not exist — a count that only ever grows, with nothing red.
    let (mut v, ino) = with_compressed(2);
    let empty = {
        let mut clean = test_image::with_root().mount_rw().unwrap();
        drift(&mut clean)
    };
    send(&mut v, ino, RELEASE_COMPRESS_BLOCKS).unwrap();
    assert_eq!(drift(&mut v), empty);
    v.truncate_compressed(ino, 0).unwrap();
    assert_eq!(drift(&mut v), empty, "a released sentinel was given back twice");
    // And the file is writable again, which is what a truncation to nothing
    // means: there is no saving left that could have been handed back.
    assert!(!v.read_inode(ino).unwrap().has(crate::flags::COMPRESS_RELEASED));
    let mut v = remount(v);
    assert_eq!(drift(&mut v), empty);
}
