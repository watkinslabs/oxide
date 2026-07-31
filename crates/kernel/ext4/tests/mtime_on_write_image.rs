//! A1 (ext4fix §7.1): a written / newly-created ext4 inode carries a real
//! wall-clock mtime/ctime, not the zero-filled 1970 epoch.
//!
//! Two halves, both proven across a REMOUNT (a committed on-disk change is the
//! only thing that survives dropping the original mount):
//!   1. create stamps atime = ctime = mtime = crtime = current_time
//!      (`ext4_new_inode` — was zero-filled, the frozen-1970 bug).
//!   2. `i_op->update_time` (the `file_update_time` backend the VFS write path
//!      fires) advances mtime + ctime to a later clock and persists them, while
//!      leaving atime untouched (S_ATIME not in the flag set).
//!
//! Image: mini-j.img — a real journaled mkfs.ext4 image (256-byte inodes, so
//! the ns / epoch-high `i_*time_extra` fields round-trip).

extern crate alloc;
mod common;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::SuperBlock;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;

// The test clock, read by the installed provider. Stepped between create and
// the update_time call so the two stamps are distinguishable.
static NOW: AtomicU64 = AtomicU64::new(0);
fn now_provider() -> u64 { NOW.load(Ordering::Relaxed) }

const T_CREATE: u64 = 1_720_000_000 * 1_000_000_000 + 250_000_000; // ~2024-07
const T_WRITE:  u64 = 1_720_003_600 * 1_000_000_000 + 750_000_000; // one hour later
fn ts(ns: u64) -> vfs::Timespec64 { vfs::Timespec64::from_clock_ns(ns) }

fn shared_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).expect("seed memdisk");
    disk
}

fn mount(disk: Arc<dyn BlockDevice>) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs, root, 0xE471_11E5, String::from("ext4"));
    (m, sb)
}

#[test]
fn create_stamps_now_and_write_advances_mtime() {
    vfs::inode_times::set_realtime_provider(now_provider);

    NOW.store(T_CREATE, Ordering::Relaxed);
    let disk = shared_disk();
    let (m, sb) = mount(disk.clone());
    let inode = m.state().create_at(b"/j.txt", 0o644).expect("create j.txt");

    // (1) create stamped the wall clock, not epoch 0.
    assert_eq!(inode.mtime(), Some(ts(T_CREATE)), "create stamps mtime");
    assert_eq!(inode.ctime(), Some(ts(T_CREATE)), "create stamps ctime");
    assert_eq!(inode.atime(), Some(ts(T_CREATE)), "create stamps atime");

    // (2) the write-path file_update_time: mtime + ctime advance, atime holds.
    NOW.store(T_WRITE, Ordering::Relaxed);
    inode.update_time(ts(T_WRITE), vfs::S_MTIME | vfs::S_CTIME).expect("update_time");
    assert_eq!(inode.mtime(), Some(ts(T_WRITE)), "in-core mtime advanced by write");
    assert_eq!(inode.ctime(), Some(ts(T_WRITE)), "in-core ctime advanced by write");
    assert_eq!(inode.atime(), Some(ts(T_CREATE)), "atime unchanged (S_ATIME not set)");

    // Persisted: remount the same disk and confirm the on-disk inode carries
    // the advanced mtime/ctime (would be 1970 before A1).
    drop(sb); drop(m);
    let (m2, _sb2) = mount(disk);
    let node = m2.state().lookup_inode_any(b"/j.txt").expect("lookup after remount");
    assert_eq!(node.mtime(), Some(ts(T_WRITE)), "remount: mtime persisted");
    assert_eq!(node.ctime(), Some(ts(T_WRITE)), "remount: ctime persisted");
    assert_eq!(node.atime(), Some(ts(T_CREATE)), "remount: atime persisted");
    assert_ne!(node.mtime(), Some(vfs::Timespec64::ZERO), "remount: not frozen at epoch");
}
