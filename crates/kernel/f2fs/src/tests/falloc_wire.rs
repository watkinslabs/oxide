//! REACHABILITY: `fallocate(2)` reaches this filesystem's implementation.
//!
//! Everything the five requests do is proved at the volume layer. What these
//! prove is that something CALLS it: each one goes through the interface's own
//! `InodeOps::fallocate` on an inode built the way a mount builds one, so
//! deleting the slot makes them fail rather than leaving the whole suite green
//! over an implementation nothing can reach.

use alloc::sync::Arc;
use alloc::vec;

use vfs::{InodeOps, InodeRef};

use crate::fallocate::uapi::{FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE,
                             FALLOC_FL_COLLAPSE_RANGE, FALLOC_FL_INSERT_RANGE};
use crate::mount::ops::F2fsOps;
use crate::mount::F2fs;
use crate::opts::Options;
use crate::test_image;
use crate::uapi::BLKSIZE;

type Disk = Arc<block::MemDisk<sync::TaskList>>;

/// A device holding `bytes`.
fn disk(bytes: &[u8]) -> Disk {
    let bs = BLKSIZE as u32;
    let blocks = bytes.len() as u64 / u64::from(bs);
    let dev: Disk = block::MemDisk::new(bs, blocks);
    let mut req = block::BlockRequest::new_write(0, blocks as u32, bytes.to_vec());
    block::BlockDevice::submit_sync(&*dev, &mut req).expect("device write");
    dev
}

/// Everything currently on `dev`.
fn drain(dev: &Disk) -> alloc::vec::Vec<u8> {
    let blocks = block::BlockDevice::capacity_blocks(&**dev);
    let mut req = block::BlockRequest::new_read(0, blocks as u32, BLKSIZE as u32);
    block::BlockDevice::submit_sync(&**dev, &mut req).expect("device read");
    req.buffer
}

/// A writable mount over the fixture image, and its device.
fn mounted_on() -> (Arc<F2fs>, Disk) {
    let dev = disk(&test_image::with_root().finish());
    let fs = F2fs::open_with(dev.clone(), "/dev/fake", true, Options::defaults()).expect("mount");
    (fs, dev)
}

/// A writable mount over the fixture image.
fn mounted() -> Arc<F2fs> { mounted_on().0 }

/// A regular file of `bytes` bytes under the root, and the interface inode for
/// it. The bytes are written through the interface so the file has real blocks.
fn file_of(fs: &Arc<F2fs>, name: &str, bytes: usize) -> InodeRef {
    let root = fs.root_inode().expect("root");
    let ctx = vfs::CreateCtx::root();
    F2fsOps.create(&root, name, vfs::mk_mode(vfs::FileType::Regular, 0o644), &ctx)
        .expect("create");
    let child = F2fsOps.lookup(&root, name).expect("lookup");
    if bytes > 0 {
        let n = vfs::FileOps::write(&F2fsOps, &child, 0, &vec![0xA5u8; bytes]).expect("write");
        assert_eq!(n, bytes, "the fixture's file was not written whole");
    }
    child
}

/// The inode's stored length and block count, read fresh from the medium.
fn stored(fs: &Arc<F2fs>, inode: &InodeRef) -> (u64, u64) {
    let ino = F2fsOps::node(inode).expect("node").ino;
    let live = fs.volume.lock().read_inode(ino).expect("read inode");
    (live.size, live.blocks)
}

#[test]
fn a_plain_allocation_through_the_slot_gives_the_file_blocks_and_a_length() {
    let fs = mounted();
    let f = file_of(&fs, "grow", 0);
    let want = 2 * BLKSIZE as u64;

    F2fsOps.fallocate(&f, 0, 0, want).expect("fallocate");

    let (size, blocks) = stored(&fs, &f);
    assert_eq!(size, want, "a plain allocation moves the length");
    assert!(blocks > 1, "the file was given no block: blocks={blocks}");
    assert_eq!(f.size(), want, "the cached length was left behind the medium");
}

#[test]
fn keeping_the_size_gives_blocks_without_moving_the_length() {
    let fs = mounted();
    let f = file_of(&fs, "keep", 0);

    F2fsOps.fallocate(&f, FALLOC_FL_KEEP_SIZE, 0, 2 * BLKSIZE as u64).expect("fallocate");

    let (size, blocks) = stored(&fs, &f);
    assert_eq!(size, 0, "KEEP_SIZE must not move the length");
    assert!(blocks > 1, "KEEP_SIZE still allocates: blocks={blocks}");
}

#[test]
fn punching_a_hole_through_the_slot_reads_back_zeroes() {
    let fs = mounted();
    let f = file_of(&fs, "punch", 3 * BLKSIZE);

    F2fsOps.fallocate(&f, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                      BLKSIZE as u64, BLKSIZE as u64).expect("fallocate");

    let (size, _) = stored(&fs, &f);
    assert_eq!(size, 3 * BLKSIZE as u64, "punching keeps the length");
    let mut buf = vec![0xFFu8; BLKSIZE];
    vfs::FileOps::read(&F2fsOps, &f, BLKSIZE as u64, &mut buf).expect("read");
    assert!(buf.iter().all(|b| *b == 0), "the punched block still holds its old bytes");
    let mut kept = vec![0u8; BLKSIZE];
    vfs::FileOps::read(&F2fsOps, &f, 0, &mut kept).expect("read");
    assert!(kept.iter().all(|b| *b == 0xA5), "punching took a block it was not asked for");
}

#[test]
fn a_collapse_through_the_slot_shortens_the_file_and_moves_its_tail_down() {
    let fs = mounted();
    let f = file_of(&fs, "collapse", 3 * BLKSIZE);
    // The last block is made distinguishable, so a collapse that moved
    // nothing would leave the wrong bytes at offset one block.
    vfs::FileOps::write(&F2fsOps, &f, 2 * BLKSIZE as u64, &vec![0x5Au8; BLKSIZE]).expect("write");

    F2fsOps.fallocate(&f, FALLOC_FL_COLLAPSE_RANGE, BLKSIZE as u64, BLKSIZE as u64)
        .expect("fallocate");

    let (size, _) = stored(&fs, &f);
    assert_eq!(size, 2 * BLKSIZE as u64, "a collapse shortens by the range it took");
    let mut buf = vec![0u8; BLKSIZE];
    vfs::FileOps::read(&F2fsOps, &f, BLKSIZE as u64, &mut buf).expect("read");
    assert!(buf.iter().all(|b| *b == 0x5A), "the tail did not move down into the gap");
}

#[test]
fn an_insert_through_the_slot_lengthens_the_file_and_moves_its_tail_up() {
    let fs = mounted();
    let f = file_of(&fs, "insert", 2 * BLKSIZE);
    vfs::FileOps::write(&F2fsOps, &f, BLKSIZE as u64, &vec![0x5Au8; BLKSIZE]).expect("write");

    F2fsOps.fallocate(&f, FALLOC_FL_INSERT_RANGE, BLKSIZE as u64, BLKSIZE as u64)
        .expect("fallocate");

    let (size, _) = stored(&fs, &f);
    assert_eq!(size, 3 * BLKSIZE as u64, "an insert lengthens by the gap it opened");
    let mut buf = vec![0u8; BLKSIZE];
    vfs::FileOps::read(&F2fsOps, &f, 2 * BLKSIZE as u64, &mut buf).expect("read");
    assert!(buf.iter().all(|b| *b == 0x5A), "the tail did not move up past the gap");
    let mut gap = vec![0xFFu8; BLKSIZE];
    vfs::FileOps::read(&F2fsOps, &f, BLKSIZE as u64, &mut gap).expect("read");
    assert!(gap.iter().all(|b| *b == 0), "the opened gap is not a hole");
}

#[test]
fn zeroing_a_range_through_the_slot_allocates_it_and_reads_back_zeroes() {
    let fs = mounted();
    let f = file_of(&fs, "zero", 2 * BLKSIZE);

    F2fsOps.fallocate(&f, FALLOC_FL_ZERO_RANGE, 0, BLKSIZE as u64).expect("fallocate");

    let mut buf = vec![0xFFu8; BLKSIZE];
    vfs::FileOps::read(&F2fsOps, &f, 0, &mut buf).expect("read");
    assert!(buf.iter().all(|b| *b == 0), "the zeroed range still holds its old bytes");
}

/// The reference stamps the modification and change times on every successful
/// request, `KEEP_SIZE` included — an allocation IS a modification — and stores
/// them, so a mount after a crash reports it.
///
/// The stamp is compared against the clock rather than against "later than
/// before", because a hosted build has no realtime source and reads zero: the
/// file's stored times are seeded to a value the clock cannot produce, and the
/// assertion is that the request replaced them with what the clock says.
#[test]
fn a_successful_allocation_stamps_the_stored_modification_time() {
    let fs = mounted();
    let f = file_of(&fs, "stamp", 0);
    let ino = F2fsOps::node(&f).expect("node").ino;
    let seed = (1u64, 7u32);
    let clock = crate::mount::write::now();
    assert_ne!(seed, clock, "the seed must be a value the clock cannot produce");
    let before = {
        let mut v = fs.volume.lock();
        v.stamp_modified(ino, seed).expect("stamp");
        v.read_inode(ino).expect("read inode")
    };
    assert_eq!(before.mtime, seed, "the fixture's stamp did not take");
    assert_eq!(before.ctime, seed);

    F2fsOps.fallocate(&f, FALLOC_FL_KEEP_SIZE, 0, BLKSIZE as u64).expect("fallocate");

    let after = fs.volume.lock().read_inode(ino).expect("read inode");
    assert_eq!(after.mtime, clock, "the modification time was not stamped");
    assert_eq!(after.ctime, clock, "the change time was not stamped");
}

/// A directory has no blocks of its own to give away, and the refusal is this
/// filesystem's own — the generic layer's type ladder never sees this call
/// because it comes in below it.
#[test]
fn a_directory_is_refused_through_the_slot() {
    let fs = mounted();
    let root = fs.root_inode().expect("root");
    assert_eq!(F2fsOps.fallocate(&root, 0, 0, BLKSIZE as u64), Err(vfs::VfsError::Einval));
}

/// A mount that cannot write refuses before it allocates anything.
#[test]
fn a_read_only_mount_refuses_the_request() {
    let (writable, dev) = mounted_on();
    file_of(&writable, "ro", BLKSIZE);
    writable.mark_clean().expect("clean");
    let fresh = disk(&drain(&dev));
    let fs = F2fs::open_with(fresh, "/dev/fake", false, Options::defaults()).expect("mount");
    let root = fs.root_inode().expect("root");
    let f = F2fsOps.lookup(&root, "ro").expect("lookup");
    assert_eq!(F2fsOps.fallocate(&f, 0, 0, BLKSIZE as u64), Err(vfs::VfsError::Erofs));
}
