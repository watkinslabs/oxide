//! Mountpoint registry (Linux `struct mountpoint` + `get_mountpoint` /
//! `put_mountpoint`, fs/namespace.c): a dentry with >=1 mount attached carries
//! a refcounted `Mountpoint` in the global `mountpoint_hashtable`, keyed by
//! dentry IDENTITY. `m_count` is the number of mounts using the dentry as their
//! mountpoint (across namespaces); the object — and the "is this dentry a
//! mountpoint" answer that umount / overmount accounting reads — must become
//! absent EXACTLY when the last mount releases it. Drop too early and an
//! overmounted dentry looks free (lost EBUSY on a still-occupied mountpoint);
//! drop too late and a leaked `Mountpoint` pins the dentry busy forever,
//! wedging umount with a phantom EBUSY.
//!
//! This locks down the refcount lifecycle the mount engine (`mount.rs` attach /
//! `detach.rs` umount) depends on but never exercises directly in `cargo test`.
//!
//! Own test binary → own copy of the vfs statics; single `#[test]` fn so the
//! shared MOUNTPOINTS table is mutated single-threaded (no SERIAL guard needed).

use std::sync::Arc;
use std::sync::atomic::Ordering;

use vfs::inode::Inode;
use vfs::mntns;
use vfs::{Dentry, FileType, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, default_file_ops, mk_mode};

// Minimal directory inode: distinct ino per dentry, no children. The registry
// keys on dentry identity (`Arc::as_ptr`), so the inode body is irrelevant.
struct DirOps;
impl InodeOps for DirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn make_dir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(DirOps), default_file_ops()).build()
}

#[test]
fn mountpoint_refcount_lifecycle() {
    let d1 = Dentry::new_root(make_dir(1));
    let d2 = Dentry::new_root(make_dir(2));

    assert!(!mntns::is_registered_mountpoint(&d1), "fresh dentry is not a mountpoint");

    // First mount on d1 → create the Mountpoint, m_count == 1.
    let mp1 = mntns::get_mountpoint(&d1);
    assert!(mntns::is_registered_mountpoint(&d1), "first get registers d1 as a mountpoint");
    assert_eq!(mp1.m_count.load(Ordering::Acquire), 1, "first get → m_count 1");

    // Overmount: a SECOND mount on the SAME dentry shares ONE object, bumping
    // m_count to 2 (not a second registry entry).
    let mp1b = mntns::get_mountpoint(&d1);
    assert!(Arc::ptr_eq(&mp1, &mp1b), "same dentry → one shared Mountpoint object");
    assert_eq!(mp1.m_count.load(Ordering::Acquire), 2, "overmount bumps m_count to 2");

    // A different dentry is independent (keyed by identity, not inode/ino).
    assert!(!mntns::is_registered_mountpoint(&d2), "d2 unaffected by d1's mounts");
    let mp2 = mntns::get_mountpoint(&d2);
    assert!(!Arc::ptr_eq(&mp1, &mp2), "distinct dentries → distinct Mountpoints");

    // Releasing ONE of d1's two holds must NOT drop the mountpoint (still busy).
    mntns::put_mountpoint(&mp1);
    assert!(mntns::is_registered_mountpoint(&d1), "one hold remains → still registered");
    assert_eq!(mp1.m_count.load(Ordering::Acquire), 1, "put drops m_count to 1");

    // Releasing the LAST hold drops it (final umount frees the Mountpoint).
    mntns::put_mountpoint(&mp1b);
    assert!(!mntns::is_registered_mountpoint(&d1), "last put unregisters d1");

    // d2 stayed registered through all of d1's churn; its own last put frees it.
    assert!(mntns::is_registered_mountpoint(&d2), "d2 still held");
    mntns::put_mountpoint(&mp2);
    assert!(!mntns::is_registered_mountpoint(&d2), "d2's last put unregisters it");

    // Re-getting after a full release allocates a FRESH object (the old one was
    // dropped, not resurrected) — m_count restarts at 1, no phantom carry-over.
    let mp1c = mntns::get_mountpoint(&d1);
    assert!(!Arc::ptr_eq(&mp1, &mp1c), "post-drop get yields a fresh Mountpoint");
    assert_eq!(mp1c.m_count.load(Ordering::Acquire), 1, "fresh get → m_count 1");
    mntns::put_mountpoint(&mp1c);
    assert!(!mntns::is_registered_mountpoint(&d1), "cleanup: d1 unregistered again");
}
