//! ext4 announces its OWN on-disk inconsistencies through the VFS
//! filesystem-error hook — the hook fanotify's `FAN_FS_ERROR` marks subscribe
//! to.
//!
//! The corruption is real and on the disk: the extent header of a file's inode
//! is given a magic number that is not an extent header's, exactly what a
//! damaged image looks like. The access that trips over it is the production
//! `i_op->bmap` path, not a hand-called reporting function, and the assertion is
//! that a watcher installed the way the kernel installs one is told which
//! filesystem failed and with which errno.
//!
//! A healthy filesystem must stay silent: an ordinary answer (a file that is
//! not there) is not an error about the filesystem, and reporting it would bury
//! the reports that matter.

extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;
use std::sync::Mutex;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;

const IMAGE: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;
/// `ext4_inode.i_block` — where the inline extent header lives.
const I_BLOCK_OFF: usize = 0x28;
/// A magic number that is not `EXT4_EXT_MAGIC`, i.e. an extent header that
/// cannot be one.
const NOT_EXTENT_MAGIC: [u8; 2] = [0x00, 0x00];

/// Reports seen by the installed hook, as `(fsid, errno)`. Process-wide because
/// the hook registry is; each test asserts on the reports naming ITS mount.
static SEEN: Mutex<std::vec::Vec<(u64, i32)>> = Mutex::new(std::vec::Vec::new());

/// Stand-in for fanotify's subscriber: the same signature, installed the same
/// way, so what reaches it is what would reach a `FAN_FS_ERROR` mark.
fn record(fsid: u64, _inode: Option<&vfs::InodeRef>, error: i32) {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((fsid, error));
}

fn install() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| vfs::set_fs_error_hook(record));
}

fn reports_for(fsid: u64) -> std::vec::Vec<i32> {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).iter()
        .filter(|(f, _)| *f == fsid).map(|(_, e)| *e).collect()
}

fn build_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    disk
}

/// Mount the fixture image and realize its superblock, so the mount has a real
/// `st_dev` for a watcher to key on. # C: O(image)
fn mount(dev: u64) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<vfs::SuperBlock>) {
    common::boot_hosted_pmm();
    install();
    let m = ext4::rootfs::Ext4Mount::open(build_disk()).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    // The mount holds only a WEAK reference to its superblock, so the caller
    // keeps it alive — without it the mount has no `st_dev` to report.
    let sb = common::realize_sb(fs, None, dev, String::from("fserr"));
    (m, sb)
}

/// Give `ino`'s inline extent header a magic number that is not an extent
/// header's, as a damaged image would have. # C: O(1)
fn corrupt_extent_header(m: &ext4::rootfs::Ext4Mount, ino: u32) {
    let mount = &m.state().mount;
    let (mut raw, _off) = mount.read_inode_bytes(ino).expect("inode bytes");
    raw[I_BLOCK_OFF..I_BLOCK_OFF + 2].copy_from_slice(&NOT_EXTENT_MAGIC);
    mount.write_inode_bytes(ino, &raw).expect("write inode bytes");
}

/// THE production-path test: reading the block map of a file whose extent
/// header is corrupt reports the failure to whoever is watching the filesystem,
/// with the errno the caller was refused with.
#[test]
fn a_corrupt_extent_header_is_reported_to_the_filesystem_watcher() {
    let dev = 0x00FE_0001;
    let (m, _sb) = mount(dev);
    let root = m.root().expect("root inode");
    let file = root.lookup("hello.txt").expect("fixture file");
    assert_eq!(file.fsid(), dev, "the mount's identity is what a watcher keys on");

    let ino = m.state().lookup_path(b"/hello.txt").expect("fixture inode number");
    corrupt_extent_header(&m, ino);

    let before = reports_for(dev).len();
    let rc = file.bmap(0);
    assert!(rc.is_err(), "the corrupt extent header refuses the access");
    let reports = reports_for(dev);
    assert_eq!(reports.len(), before + 1, "exactly one report for one failure");
    assert_eq!(reports[before], rc.unwrap_err() as i32,
               "the reported number is the errno the caller was refused with, POSITIVE");
}

/// A HEALTHY filesystem stays silent. An ordinary answer — a name that is not
/// there, a block that is not mapped — is not an error about the filesystem.
#[test]
fn a_healthy_filesystem_reports_nothing() {
    let dev = 0x00FE_0002;
    let (m, _sb) = mount(dev);
    let root = m.root().expect("root inode");
    let before = reports_for(dev).len();
    assert!(root.lookup("does-not-exist").is_err());
    let file = root.lookup("hello.txt").expect("fixture file");
    // A block past the end of the file is a hole, not a failure.
    assert!(file.bmap(1 << 20).is_ok());
    assert_eq!(reports_for(dev).len(), before, "nothing to report on a healthy filesystem");
}
