//! Per-namespace mount cap WIRED into the live mount engine (Linux
//! `count_mounts` in `attach_recursive_mnt` + `nr_mounts--` in `umount_tree`).
//!
//! `mntns_mount_max.rs` exercises the counter API in isolation; THIS test drives
//! the cap through the real `register`/`unregister`/`copy_mnt_ns` engine paths to
//! prove the accounting is actually connected:
//!   * each successful `register` (graft via `attach`) reserves+commits one slot,
//!     so `nr_mounts` tracks the live mount count;
//!   * a graft that would exceed `sysctl_mount_max` is refused with ENOSPC and
//!     leaves NO partial reservation (`pending_mounts == 0`);
//!   * `unregister` (umount) frees a slot, immediately re-grantable;
//!   * `copy_mnt_ns` accounts the cloned subtree into the child ns `nr_mounts`.
//!
//! FAILS-BEFORE this wiring: `attach`/`unregister` never touched the counters, so
//! `nr_mounts` stayed 0 forever and `register` never returned ENOSPC — both the
//! count assertions and the ENOSPC assertion below would fail.
//!
//! Own test binary → own copy of the vfs statics; `SERIAL`-guarded + a unique ns
//! so the process-global `MOUNTS` / `SYSCTL_MOUNT_MAX` are mutated deterministically.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{mntns, FileType, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, default_file_ops, mk_mode};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

const NS: u64 = 0x4341_5001; // "CAP" ns, clear of sibling test ids.
const CHILD: u64 = 0x4341_5002;

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| NS);
    common::install();
    g
}

struct TFs(u64);
impl FileSystem for TFs {
    fn name(&self) -> &str { "capfs" }
    fn root(&self) -> Option<InodeRef> { Some(make_tdir(self.0)) }
}
struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn make_tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TFs(ino)) }

#[test]
fn cap_wired_through_register_umount_copy() {
    let _g = guard();
    // Cap the ns at 3 live mounts so we needn't graft 100k.
    mntns::set_sysctl_mount_max(3);
    mntns::ns_get_or_create(NS);
    assert_eq!(mntns::ns_nr_mounts(NS), 0, "fresh ns has no mounts");

    // The root graft + two more fill the ns exactly to the ceiling, and each
    // bumps the live count by one (the reserve→commit wired into `attach`).
    common::register("/", fs(0x1)).expect("root mount under cap");
    assert_eq!(mntns::ns_nr_mounts(NS), 1, "root graft counted");
    common::register("/a", fs(0x2)).expect("a under cap");
    assert_eq!(mntns::ns_nr_mounts(NS), 2, "second graft counted");
    common::register("/b", fs(0x3)).expect("b == ceiling");
    assert_eq!(mntns::ns_nr_mounts(NS), 3, "third graft hits the ceiling");

    // The next graft would exceed the cap → ENOSPC, reserving nothing.
    assert_eq!(common::register("/c", fs(0x4)), Err(VfsError::Enospc),
        "over-cap graft refused with ENOSPC");
    assert_eq!(mntns::ns_nr_mounts(NS), 3, "rejected graft did not change live count");
    assert_eq!(mntns::ns_pending_mounts(NS), 0, "rejected graft left no reservation");

    // umount frees a slot, immediately re-grantable.
    assert_eq!(common::unregister("/b"), 1, "umount /b");
    assert_eq!(mntns::ns_nr_mounts(NS), 2, "umount dropped a live slot");
    common::register("/c", fs(0x5)).expect("freed slot re-grantable");
    assert_eq!(mntns::ns_nr_mounts(NS), 3, "re-graft back at ceiling");

    // copy_mnt_ns accounts the cloned subtree into the child ns (Linux sums
    // nr_mounts over the copy; the copy itself is not sysctl-bounded).
    vfs::mount::copy_mnt_ns(NS, CHILD);
    assert_eq!(mntns::ns_nr_mounts(CHILD), 3, "child ns inherits the live count");

    // Restore the default ceiling (defensive; this binary owns its statics).
    mntns::set_sysctl_mount_max(mntns::DEFAULT_MOUNT_MAX);
}
