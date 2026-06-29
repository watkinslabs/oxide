//! [D20]: `pivot_root(2)` validation, faithful to Linux
//! `SYSCALL_DEFINE2(pivot_root)` (`fs/namespace.c`). The safety rejections that
//! were missing (all -EINVAL):
//!   * the new_root mount must not be MNT_LOCKED
//!     (`new_mnt->mnt.mnt_flags & MNT_LOCKED`);
//!   * none of {the mount put_old resides on, the new_root's parent, the current
//!     root's parent} may be SHARED — a shared mountpoint would corrupt its
//!     peers when the re-root mutates it (`IS_MNT_SHARED(old_mnt) ||
//!     IS_MNT_SHARED(new_mnt->mnt_parent) || IS_MNT_SHARED(root_mnt->mnt_parent)`).
//! A clean pivot between private mounts still succeeds.
//! Exercises the real global mount engine via the hosted fixture, no QEMU.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::mount::Propagation;
use vfs::{FileType, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, default_file_ops, mk_mode};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0xD7);
    common::install();
    g
}

struct TFs { root_ino: u64 }
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
    fn root(&self) -> Option<InodeRef> { Some(make_tdir(self.root_ino)) }
}
struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn make_tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TFs { root_ino: ino }) }

// A clean pivot_root between private mounts still succeeds.
#[test]
fn clean_pivot_root_succeeds() {
    let _g = guard();
    common::register("/", fs(0xA)).expect("root");
    common::register("/nr", fs(0xB)).expect("newroot");
    common::pivot_root("/nr", "/nr/old").expect("clean pivot");
}

// [D20] new_root mount marked MNT_LOCKED → EINVAL.
#[test]
fn pivot_locked_new_root_is_einval() {
    let _g = guard();
    common::register("/", fs(0xA)).expect("root");
    common::register("/nr", fs(0xB)).expect("newroot");
    common::mount_at_path_exact("/nr").unwrap().set_internal_flag(vfs::mount::MNT_LOCKED);
    assert!(matches!(common::pivot_root("/nr", "/nr/old"), Err(VfsError::Einval)),
            "pivot_root with a MNT_LOCKED new_root must be EINVAL");
}

// [D20] new_root's PARENT mount is shared → EINVAL (re-rooting would mutate a
// shared mountpoint).
#[test]
fn pivot_shared_new_root_parent_is_einval() {
    let _g = guard();
    common::register("/", fs(0xA)).expect("root");
    common::register("/nr", fs(0xB)).expect("newroot");
    // Share the parent (root) AFTER attaching /nr so no propagation fires.
    common::set_propagation("/", Propagation::Shared).expect("share root");
    assert!(matches!(common::pivot_root("/nr", "/nr/old"), Err(VfsError::Einval)),
            "pivot_root onto a new_root whose parent is shared must be EINVAL");
}

// [D20] the mount put_old resides on is shared → EINVAL.
#[test]
fn pivot_shared_put_old_mount_is_einval() {
    let _g = guard();
    common::register("/", fs(0xA)).expect("root");
    common::register("/nr", fs(0xB)).expect("newroot");
    // put_old (/nr/old) resides on the /nr mount; sharing it triggers the
    // IS_MNT_SHARED(old_mnt) rejection.
    common::set_propagation("/nr", Propagation::Shared).expect("share nr");
    assert!(matches!(common::pivot_root("/nr", "/nr/old"), Err(VfsError::Einval)),
            "pivot_root with a shared put_old mount must be EINVAL");
}
