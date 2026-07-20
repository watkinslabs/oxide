//! superblock-D6: ext4 reports its backing-device `dev_t` via
//! `FileSystem::dev_id`, so the mount engine `sget`-shares ONE `SuperBlock`
//! across two mounts of the same device (the real `major:minor` as `s_dev`).
//! The serial-bound rootfs (no resolvable dev_t) keeps `dev_id() == None` → a
//! fresh per-mount anon SB, never a mis-keyed share.

extern crate alloc;
mod common;
use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::superblock::sget;

const MINI: &[u8] = include_bytes!("mini.img");
const BLOCK_SIZE: u32 = 512;

fn disk() -> Arc<dyn BlockDevice> {
    let cap = (MINI.len() as u64) / (BLOCK_SIZE as u64);
    let d: Arc<MemDisk<TaskList>> = MemDisk::new(BLOCK_SIZE, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: MINI.to_vec() };
    d.submit_sync(&mut req).expect("memdisk write");
    d
}

/// `open_with_dev(_, Some)` reports the stored dev_t; plain `open` (the
/// serial-bound rootfs gap) reports `None`.
#[test]
fn dev_id_reports_stored_dev_t() {
    let with: Arc<dyn FileSystem> =
        ext4::rootfs::Ext4Mount::open_with_dev(disk(), Some(0x0000_fe00)).expect("open_with_dev");
    assert_eq!(with.dev_id(), Some(0x0000_fe00), "ext4 reports its backing dev_t");
    let none: Arc<dyn FileSystem> = ext4::rootfs::Ext4Mount::open(disk()).expect("open");
    assert_eq!(none.dev_id(), None, "no resolvable dev_t → None (fresh anon SB)");
}

#[test]
fn registered_dev_id_publishes_ext4_sysfs_name() {
    let name = "vdb738sysfs";
    let idx = block::registry::register(name, disk());
    assert!(idx != 0, "registered block disk");
    let dev_t = block::registry::dev_t_of(name, idx).unwrap() as u64;
    let fs: Arc<dyn FileSystem> =
        ext4::rootfs::Ext4Mount::open_with_dev(disk(), Some(dev_t)).expect("open_with_dev");
    assert_eq!(fs.sysfs_name(), Some(String::from(name)));
    let sb = common::realize_sb(fs.clone(), fs.root(), fs.dev_id().unwrap(), String::from("/dev/vdb738sysfs"));
    assert_eq!(sb.s_sysfs_name(), name);
    assert_ne!(sb.s_id, name, "sysfs name is not derived from s_id");
}

/// Two ext4 mounts of the SAME dev_t share ONE `SuperBlock` via `sget` — exactly
/// what the mount engine's `build_sb` does for a `dev_id() == Some` backend.
#[test]
fn same_dev_two_mounts_share_superblock_via_sget() {
    let dev_t: u64 = 0xCA00_0001; // unique within this test binary
    let a: Arc<dyn FileSystem> =
        ext4::rootfs::Ext4Mount::open_with_dev(disk(), Some(dev_t)).expect("a");
    let b: Arc<dyn FileSystem> =
        ext4::rootfs::Ext4Mount::open_with_dev(disk(), Some(dev_t)).expect("b");
    assert_eq!(a.dev_id(), Some(dev_t));
    assert_eq!(b.dev_id(), Some(dev_t));

    // Mirror build_sb: sget keyed on dev_id → the second build is NOT run.
    let sa = sget(a.dev_id().unwrap(),
        || common::realize_sb(a.clone(), a.root(), a.dev_id().unwrap(), String::from("ext4")));
    let sb = sget(b.dev_id().unwrap(),
        || common::realize_sb(b.clone(), b.root(), b.dev_id().unwrap(), String::from("ext4")));
    assert!(Arc::ptr_eq(&sa, &sb), "same dev_t → one shared SuperBlock (sget hit)");
    assert_eq!(sa.s_dev, dev_t, "shared SB carries the real dev_t as s_dev");
    assert!(sa.s_active() >= 2, "each sget reference holds one s_active");
}
