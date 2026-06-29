//! dcache-D15: `Dentry::is_mountpoint(ns)` is NAMESPACE-SCOPED (Linux mount
//! crossing is per-mount-namespace — the same dentry can be covered in one ns
//! and bare in another). The ledger flagged the old any-ns shape
//! (`!mounted_mounts.is_empty()`) as a cross-ns false positive; the current
//! code keys the covering-mount test on `ns`. This locks the per-ns behavior so
//! a regression back to an any-ns test fails here.

use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{Dentry, FileType, InodeRef, KResult, VfsError};

struct Dir(u64);
impl Inode for Dir {
    fn ino(&self) -> vfs::Ino { self.0 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn dir(ino: u64) -> InodeRef { Arc::new(Dir(ino)) }

const NS_A: u64 = 11;
const NS_B: u64 = 22;

#[test]
fn is_mountpoint_is_per_namespace() {
    let d = Dentry::new_root(dir(1));
    // Bare in every namespace.
    assert!(!d.is_mountpoint(NS_A));
    assert!(!d.is_mountpoint(NS_B));
    assert!(d.mounted_mount(NS_A).is_none());

    // Cover it ONLY in NS_A.
    d.set_mounted_mount(NS_A, Some(0xABCD));
    assert!(d.is_mountpoint(NS_A), "covered in NS_A");
    assert_eq!(d.mounted_mount(NS_A), Some(0xABCD));
    // The any-ns bug would report NS_B as a mountpoint too — it must NOT.
    assert!(!d.is_mountpoint(NS_B), "must be bare in NS_B (cross-ns false positive)");
    assert!(d.mounted_mount(NS_B).is_none());
}

#[test]
fn clear_covering_mount_in_one_ns_only() {
    let d = Dentry::new_root(dir(2));
    d.set_mounted_mount(NS_A, Some(1));
    d.set_mounted_mount(NS_B, Some(2));
    assert!(d.is_mountpoint(NS_A) && d.is_mountpoint(NS_B));

    // Uncover NS_A; NS_B must survive.
    d.set_mounted_mount(NS_A, None);
    assert!(!d.is_mountpoint(NS_A), "NS_A uncovered");
    assert!(d.is_mountpoint(NS_B), "NS_B coverage untouched");
    assert_eq!(d.mounted_mount(NS_B), Some(2));
}
