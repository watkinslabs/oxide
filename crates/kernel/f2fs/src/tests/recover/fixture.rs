//! The fixture every recovery test shares: a checkpointed volume, a way to
//! add a block the way a fixed writer would, and a way to abandon the medium
//! without a checkpoint.

use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::*;
use crate::volume::dnode::{put32, put64};
use crate::volume::recover::marks;
use crate::volume::{NewInode, Volume};
use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;
use syscall::errno::Errno;

pub const NOW: (u64, u32) = (1_800_000_000, 7);
/// Two blocks' worth of bytes, which is past what an inode holds inline, so
/// the file's addresses land in the inode's array where a chain can carry
/// them.
pub const BODY: usize = 2 * BLKSIZE;

pub fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW }
}

pub fn pattern(seed: u8) -> Vec<u8> { (0..BODY).map(|i| seed ^ (i as u8)).collect() }

/// A volume with one checkpointed file of two blocks.
pub fn checkpointed(name: &[u8]) -> (Volume<MemImage>, u32, Vec<u8>) {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, name, &spec(), None).expect("create");
    let body = pattern(0x5A);
    v.write_file(ino, 0, &body).expect("write");
    v.commit().expect("commit");
    (v, ino, body)
}

/// Append one block to `ino` the way a fixed writer would: the data block into
/// the data log, then the inode block into the node log with the marks the
/// walk looks for.
pub fn append_block(v: &mut Volume<MemImage>, ino: u32, byte: u8, fsync: bool) -> (u32, u32) {
    let data = vec![byte; BLKSIZE];
    let index = (BODY / BLKSIZE) as u16;
    let at = v.write_data(ino, ino, index, false, NULL_ADDR, &data).expect("data");
    let inode = v.read_inode(ino).expect("inode");
    let mut block = v.inode_bytes(ino).expect("inode bytes");
    put32(&mut block, inode.addr_base() + index as usize * 4, at);
    put64(&mut block, I_SIZE, (BODY + BLKSIZE) as u64);
    let flag = marks::flag_word(0, fsync, false, true);
    let node = v.write_chained_node(ino, ino, block, flag).expect("node");
    (at, node)
}

/// Append one block through the REAL path — the writer a caller uses — and
/// return what the whole file should read as afterwards.
///
/// This is the pairing that matters: `write_file` lays down the data and the
/// nodes, `fsync` marks and chains them, and nothing tells the two they are
/// being tested together. A crafted chain proves recovery reads what it is
/// given; only this proves the writer gives it what it reads.
pub fn grow(v: &mut Volume<MemImage>, ino: u32, byte: u8) -> Vec<u8> {
    let mut want = whole(v, ino);
    let tail = vec![byte; BLKSIZE];
    v.write_file(ino, want.len() as u64, &tail).expect("write");
    want.extend_from_slice(&tail);
    want
}

/// The same, made durable the way a caller would.
pub fn grow_and_fsync(v: &mut Volume<MemImage>, ino: u32, byte: u8) -> Vec<u8> {
    let want = grow(v, ino, byte);
    assert_eq!(v.fsync(ino).expect("fsync"), crate::volume::fsync::CpReason::None,
               "the fixture's file must be in the state the chain path serves");
    want
}

/// The medium's bytes, mounted again as a crash would leave them.
///
/// The mount itself replays: nothing may read a volume in the state a crash
/// left it in, so by the time this returns the chain is gone and its contents
/// are in the file. Tests assert what the file HOLDS, which is the contract a
/// caller was given.
pub fn crash(v: Volume<MemImage>) -> Volume<MemImage> {
    remount(v.into_source().snapshot(), true)
}

/// The same bytes, mounted where the mount is expected to refuse.
pub fn try_crash(v: Volume<MemImage>, write: bool, opts: Options)
    -> Result<Volume<MemImage>, Errno> {
    let img = MemImage::from_bytes(BLKSIZE as u32, v.into_source().snapshot());
    Volume::mount_with(img, opts, write)
}

/// The same bytes, mounted so that the chain is still THERE.
///
/// Asking for a read-only MOUNT is not enough and has not been since the
/// mount learned to lift its own read-only for a repair: a read-only mount
/// over a writable medium replays like any other. What leaves the tail
/// standing is declining the roll-forward, which is the one request that
/// makes a mount walk past a chain it could have replayed — so that is what
/// this fixture asks for, on a mount that also may not write.
pub fn crash_ro(v: Volume<MemImage>) -> Volume<MemImage> {
    remount_opts(v.into_source().snapshot(), false,
                 Options { recovery: false, ..Options::defaults() })
}

/// A checkpointed file on a volume whose last checkpoint claims a clean
/// shutdown, so the mount hook skips and a test can drive the pass by hand and
/// read what it reports.
///
/// The state is deliberately impossible on a real volume — nothing can be
/// written after the checkpoint that ends a mount — and exists only because
/// the mount hook discards the report it gets.
pub fn checkpointed_unmounted(name: &[u8]) -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, name, &spec(), None).expect("create");
    v.write_file(ino, 0, &pattern(0x5A)).expect("write");
    v.commit_with(crate::volume::commit::CpReason::Umount).expect("commit");
    (v, ino)
}

pub fn remount(bytes: Vec<u8>, write: bool) -> Volume<MemImage> {
    remount_opts(bytes, write, Options::defaults())
}

/// A remount under a stated option set, for the cases where the option is what
/// is under test — the log a write lands in is chosen by the mount, so a
/// remount under different options looks for the chain somewhere else.
pub fn remount_opts(bytes: Vec<u8>, write: bool, opts: Options) -> Volume<MemImage> {
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), opts, write)
        .expect("remount")
}

/// A checkpointed file of two blocks, on a volume mounted under `opts`.
pub fn checkpointed_opts(name: &[u8], opts: Options) -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_opts(opts).expect("mount");
    let ino = v.create(ROOT_INO, name, &spec(), None).expect("create");
    v.write_file(ino, 0, &pattern(0x5A)).expect("write");
    v.commit().expect("commit");
    (v, ino)
}

pub fn whole(v: &Volume<MemImage>, ino: u32) -> Vec<u8> {
    let inode = v.read_inode(ino).expect("inode");
    v.read_whole(&inode, ino).expect("read")
}

/// Overwrite four bytes of a block's footer in a crashed image.
pub fn poke_footer(bytes: &mut [u8], addr: u32, field: usize, value: u32) {
    let at = addr as usize * BLKSIZE + NODE_FOOTER_OFF + field;
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
