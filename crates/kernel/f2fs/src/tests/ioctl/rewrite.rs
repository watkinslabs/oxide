//! Compressing and decompressing a file in place, through the real commands.
//!
//! Every case checks the SHAPE on the medium — the sentinel, the reservations
//! and the two counts, after a remount — and the file's bytes through the
//! ordinary reader. A rewrite that changed the shape and lost a byte, or kept
//! the bytes and left the counts describing the old shape, passes neither.

use alloc::vec::Vec;
use sectors::MemImage;
use syscall::errno::Errno;

use crate::compress::algo::COMPRESS_LZ4;
use crate::compress::plan;
use crate::ioctl::entry::{handle, Answer};
use crate::ioctl::perm::Ctx;
use crate::ioctl::req::Extra;
use crate::ioctl::uapi::*;
use crate::mode::S_IFREG;
use crate::opts::{CompressMode, Options};
use crate::test_image::{self, ROOT_INO};
use crate::uapi::{le32, BLKSIZE, I_COMPRESS_ALGORITHM, I_FLAGS, I_LOG_CLUSTER_SIZE};
use crate::volume::dnode::put32;
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 11);
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
    handle(v, ino, cmd, &[], &Extra::default(), &root())
}

fn patterned(n: usize) -> Vec<u8> { (0..n).map(|i| ((i / 64) % 11) as u8).collect() }

/// A volume whose compression the CALLER drives, holding one compressed file.
/// # C: O(1 image)
fn user_driven() -> (Volume<MemImage>, u32) { mounted(CompressMode::User) }

/// # C: O(1 image)
fn mounted(mode: CompressMode) -> (Volume<MemImage>, u32) {
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_COMPRESSION;
    let mut o = Options::defaults();
    o.compress.mode = mode;
    let mut v = b.mount_opts(o).unwrap();
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
    (v, ino)
}

/// # C: O(image)
fn remount(mut v: Volume<MemImage>, mode: CompressMode) -> Volume<MemImage> {
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    let mut o = Options::defaults();
    o.compress.mode = mode;
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), o, true).unwrap()
}

/// Whether the cluster starting at file block `first` is stored as an image.
/// # C: O(cluster blocks)
fn is_compressed(v: &Volume<MemImage>, ino: u32, first: u64) -> bool {
    let inode = v.read_inode(ino).unwrap();
    let g = v.geometry(&inode).unwrap();
    let a = v.cluster_addrs(&inode, ino, &g, first).unwrap();
    plan::compressed_extent(&a).is_some()
}

fn whole(v: &Volume<MemImage>, ino: u32) -> Vec<u8> {
    let inode = v.read_inode(ino).unwrap();
    v.read_whole(&inode, ino).unwrap()
}

#[test]
fn a_mount_the_caller_drives_writes_plain_until_it_is_asked_otherwise() {
    // Without this the command has nothing to do: the mount would already
    // have compressed everything on the way in.
    let (mut v, ino) = user_driven();
    let data = patterned(2 * CS * BLKSIZE);
    v.write_compressed(ino, 0, &data).unwrap();
    assert!(!is_compressed(&v, ino, 0), "a caller-driven mount compressed on its own");
    assert_eq!(v.compr_blocks(ino).unwrap(), 0);
    assert_eq!(whole(&v, ino), data);
}

#[test]
fn the_command_compresses_every_cluster_and_the_bytes_survive() {
    let (mut v, ino) = user_driven();
    let data = patterned(2 * CS * BLKSIZE);
    v.write_compressed(ino, 0, &data).unwrap();
    let blocks = v.read_inode(ino).unwrap().blocks;
    send(&mut v, ino, COMPRESS_FILE).unwrap();
    let v = remount(v, CompressMode::User);
    assert!(is_compressed(&v, ino, 0), "the first cluster was left plain");
    assert!(is_compressed(&v, ino, CS as u64), "the second cluster was left plain");
    assert!(v.compr_blocks(ino).unwrap() > 0, "nothing was recorded as saved");
    // The cluster is still charged for every slot it holds, so the file's
    // block count does not move: the saving is what a release hands back.
    assert_eq!(v.read_inode(ino).unwrap().blocks, blocks);
    assert_eq!(whole(&v, ino), data);
}

#[test]
fn the_command_decompresses_every_cluster_and_the_bytes_survive() {
    let (mut v, ino) = user_driven();
    let data = patterned(2 * CS * BLKSIZE);
    v.write_compressed(ino, 0, &data).unwrap();
    send(&mut v, ino, COMPRESS_FILE).unwrap();
    assert!(is_compressed(&v, ino, 0));
    send(&mut v, ino, DECOMPRESS_FILE).unwrap();
    let v = remount(v, CompressMode::User);
    assert!(!is_compressed(&v, ino, 0), "a cluster survived the decompression");
    assert!(!is_compressed(&v, ino, CS as u64));
    assert_eq!(v.compr_blocks(ino).unwrap(), 0, "a saving outlived the image it came from");
    assert_eq!(whole(&v, ino), data);
}

#[test]
fn compressing_a_file_that_is_already_compressed_changes_nothing() {
    let (mut v, ino) = user_driven();
    let data = patterned(CS * BLKSIZE);
    v.write_compressed(ino, 0, &data).unwrap();
    send(&mut v, ino, COMPRESS_FILE).unwrap();
    let saved = v.compr_blocks(ino).unwrap();
    let blocks = v.read_inode(ino).unwrap().blocks;
    send(&mut v, ino, COMPRESS_FILE).unwrap();
    assert_eq!(v.compr_blocks(ino).unwrap(), saved, "the saving was counted twice");
    assert_eq!(v.read_inode(ino).unwrap().blocks, blocks);
    assert_eq!(whole(&v, ino), data);
}

#[test]
fn a_cluster_the_file_stops_part_way_through_is_left_alone() {
    // An image covering blocks past the end would be rewritten by the very
    // next append, so the format does not make one.
    let (mut v, ino) = user_driven();
    let data = patterned(CS * BLKSIZE + 3 * BLKSIZE);
    v.write_compressed(ino, 0, &data).unwrap();
    send(&mut v, ino, COMPRESS_FILE).unwrap();
    assert!(is_compressed(&v, ino, 0));
    assert!(!is_compressed(&v, ino, CS as u64), "a part cluster was compressed");
    assert_eq!(whole(&v, ino), data);
}

#[test]
fn a_cluster_with_a_hole_in_it_is_left_alone() {
    let (mut v, ino) = user_driven();
    let data = patterned(BLKSIZE);
    // Only the last block of the first cluster, and enough after it that the
    // cluster lies wholly inside the file.
    v.write_compressed(ino, 3 * BLKSIZE as u64, &data).unwrap();
    v.write_compressed(ino, (CS * BLKSIZE) as u64, &data).unwrap();
    send(&mut v, ino, COMPRESS_FILE).unwrap();
    assert!(!is_compressed(&v, ino, 0), "a sparse cluster was compressed");
}

#[test]
fn a_mount_that_compresses_for_itself_refuses_both_commands() {
    // Rewriting by hand only means anything when the mount is not doing it,
    // and a caller that got success on such a mount would believe it had
    // changed something.
    let (mut v, ino) = mounted(CompressMode::Fs);
    v.write_compressed(ino, 0, &patterned(CS * BLKSIZE)).unwrap();
    for cmd in [COMPRESS_FILE, DECOMPRESS_FILE] {
        assert_eq!(send(&mut v, ino, cmd).map(|_| ()), Err(Errno::Eopnotsupp), "{cmd:#x}");
    }
}

#[test]
fn a_file_that_is_not_compressed_at_all_is_refused() {
    let (mut v, _) = user_driven();
    let ino = v.create(ROOT_INO, b"p",
                       &NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW },
                       None).unwrap();
    for cmd in [COMPRESS_FILE, DECOMPRESS_FILE] {
        assert_eq!(send(&mut v, ino, cmd).map(|_| ()), Err(Errno::Einval), "{cmd:#x}");
    }
}

#[test]
fn a_released_file_is_refused_both_commands() {
    // Its saved blocks belong to the volume now, and a rewrite would spend
    // them without asking for them back.
    let (mut v, ino) = mounted(CompressMode::Fs);
    v.write_compressed(ino, 0, &patterned(CS * BLKSIZE)).unwrap();
    v.release_compress_blocks(ino).unwrap();
    let mut v = remount(v, CompressMode::User);
    for cmd in [COMPRESS_FILE, DECOMPRESS_FILE] {
        assert_eq!(send(&mut v, ino, cmd).map(|_| ()), Err(Errno::Einval), "{cmd:#x}");
    }
}

#[test]
fn a_description_that_cannot_write_is_refused() {
    let (mut v, ino) = user_driven();
    v.write_compressed(ino, 0, &patterned(CS * BLKSIZE)).unwrap();
    let c = Ctx { fmode_write: false, ..root() };
    assert_eq!(handle(&mut v, ino, COMPRESS_FILE, &[], &Extra::default(), &c).map(|_| ()),
               Err(Errno::Ebadf));
}
