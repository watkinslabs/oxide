//! dcache-D25: `d_invalidate` must detach submounts in the invalidated subtree
//! (Linux `detach_mounts`). Builds a dir subtree, mounts a fs on a dentry
//! WITHIN it, then invalidates the subtree root and asserts the mount is gone.
//! Drives the real (global) mount engine via the hosted dentry-identity
//! fixture; serializes on `SERIAL` and resets the ns provider like
//! `mount_tree.rs` (one process-global table).

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0);
    common::install();
    g
}

struct TFs { root_ino: u64 }
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
    fn root(&self) -> Option<InodeRef> { Some(Arc::new(TDir { ino: self.root_ino })) }
}
struct TDir { ino: u64 }
impl Inode for TDir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TFs { root_ino: ino }) }

// d_invalidate detaches a mount that covers a dentry WITHIN the invalidated
// subtree (Linux detach_mounts(child)). The mountpoint `/a/b/m` is a descendant
// of `/a`; after `d_invalidate(/a)` the mount is gone from the table and the
// mountpoint dentry no longer crosses.
#[test]
fn d_invalidate_detaches_submount() {
    let _g = guard();
    vfs::mount::set_current_ns_provider(|| 0xD25);
    common::register("/", fs(0x1)).expect("root");
    // Subtree under /a, with a real mount on the descendant /a/b/m.
    let a = common::dentry("/a");
    let mp = common::dentry("/a/b/m");
    common::register("/a/b/m", fs(0x42)).expect("submount");
    // Mount is present before invalidation.
    assert!(vfs::mount::mount_at_path_exact(&mp).is_some(), "submount present pre-invalidate");
    assert_eq!(common::mount_root_at("/a/b/m").map(|i| i.ino()), Some(0x42), "submount root pre");

    // Invalidate the subtree root → must detach the submount (the pre-fix bug:
    // the mount survives because d_invalidate only unhashed dentries).
    vfs::d_invalidate(&a);

    assert!(vfs::mount::mount_at_path_exact(&mp).is_none(), "submount GONE post-invalidate");
    assert!(common::mount_root_at("/a/b/m").is_none(), "no mount root post");
    assert!(!mp.is_mountpoint(0xD25), "mountpoint dentry no longer crosses");
    // And the table holds only the root mount.
    let left: Vec<u64> = vfs::mount::snapshot().into_iter().map(|m| m.mnt_id).collect();
    assert_eq!(left.len(), 1, "only the root mount remains: {left:?}");
}
