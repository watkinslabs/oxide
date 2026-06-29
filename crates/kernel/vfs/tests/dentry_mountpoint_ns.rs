//! dcache-D15: `Dentry::is_mountpoint(ns)` is namespace-scoped (Linux mount
//! crossing is per-mount-namespace — the same dentry can be covered in one ns
//! and bare in another). An any-ns test would be a cross-ns false positive that
//! makes a walk in ns B wrongly cross a mount that exists only in ns A. The
//! covering mount id is stored per-ns (`set_mounted_mount`) and queried per-ns
//! (`mounted_mount`/`is_mountpoint`). Regression guard for the ledger's stale
//! "is_mountpoint ignores namespace" claim — the ns parameter is now mandatory.

use std::sync::Arc;

use vfs::dentry::Dentry;
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

struct Dir { ino: u64 }
impl Inode for Dir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn dir(ino: u64) -> InodeRef { Arc::new(Dir { ino }) }

const NS_A: u64 = 0xA;
const NS_B: u64 = 0xB;

#[test]
fn mountpoint_is_per_namespace() {
    let d = Dentry::new_root(dir(1));
    // Bare in every namespace to start.
    assert!(!d.is_mountpoint(NS_A));
    assert!(!d.is_mountpoint(NS_B));
    assert!(d.mounted_mount(NS_A).is_none());

    // Cover it in ns A only.
    d.set_mounted_mount(NS_A, Some(0x100));
    assert!(d.is_mountpoint(NS_A), "covered in ns A");
    assert_eq!(d.mounted_mount(NS_A), Some(0x100));
    // ns B must NOT see ns A's mount (no cross-ns false positive).
    assert!(!d.is_mountpoint(NS_B), "ns B is unaffected by ns A's mount");
    assert!(d.mounted_mount(NS_B).is_none());
}

#[test]
fn unmount_in_one_ns_keeps_the_other() {
    let d = Dentry::new_root(dir(2));
    d.set_mounted_mount(NS_A, Some(0x200));
    d.set_mounted_mount(NS_B, Some(0x201));
    assert!(d.is_mountpoint(NS_A) && d.is_mountpoint(NS_B));
    // Detach in ns A; ns B still covered.
    d.set_mounted_mount(NS_A, None);
    assert!(!d.is_mountpoint(NS_A), "ns A detached");
    assert!(d.is_mountpoint(NS_B), "ns B still covered");
    assert_eq!(d.mounted_mount(NS_B), Some(0x201));
}
