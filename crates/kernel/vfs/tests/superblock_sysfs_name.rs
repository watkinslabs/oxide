//! superblock-D (`s_sysfs_name`): Linux keeps the programmatic sysfs handle in
//! `super_block.s_sysfs_name`, separate from human/debug `s_id`. Empty means
//! `FS_IOC_GETFSSYSFSPATH` returns `ENOTTY`; a backend publishes the exact
//! sysfs handle during fill-super.

use std::sync::Arc;

mod common;

use vfs::fs::FileSystem;
use vfs::superblock::next_anon_dev;
use vfs::SuperBlock;

struct SFs;
impl FileSystem for SFs {
    fn name(&self) -> &str { "sfs" }
}

fn sb() -> Arc<SuperBlock> {
    common::realize_sb(Arc::new(SFs), None, next_anon_dev(), String::from("debug-id-is-not-sysfs"))
}

#[test]
fn fresh_sb_has_no_sysfs_name() {
    let sb = sb();
    assert!(!sb.has_sysfs_name());
    assert_eq!(sb.s_sysfs_name(), "");
}

#[test]
fn set_sysfs_name_publishes_independent_handle() {
    let sb = sb();
    sb.set_sysfs_name("vda1");
    assert!(sb.has_sysfs_name());
    assert_eq!(sb.s_sysfs_name(), "vda1");
    assert_eq!(sb.s_id, "debug-id-is-not-sysfs");
}

#[test]
fn set_sysfs_name_clamps_to_linux_storage_width() {
    let sb = sb();
    sb.set_sysfs_name("123456789012345678901234567890123456TAIL");
    assert_eq!(sb.s_sysfs_name(), "123456789012345678901234567890123456");
}
