//! procfs's OWN `kernfs::PseudoDir` root (D1d). Replaces the shared devfs
//! ROOTS write-bus for `/proc/{sys,net,self}`: every such node is inserted
//! into `PROC_REG` and reached via `ProcRootInode`/`ProcPidDirInode` bridges,
//! so procfs owns its tree under its own mount instead of reading subtrees
//! back out of the global devfs registry. `overlay = false` — there is no
//! on-disk `/proc` to merge. Mirrors `sysfs::root` (D1c).

use alloc::sync::Arc;
use kernfs::PseudoDir;
use sync::{Spinlock, TaskList as LockClass};
use vfs::InodeRef;

/// procfs filesystem identity for stat(2) `st_dev` (distinct from
/// `DEVFS_FSID`/`SYSFS_FSID` so `/proc`, `/dev`, `/sys` no longer alias).
pub const PROCFS_FSID: u64 = 0x0102_1994_0000_0003;

/// The single procfs sub-tree root holding `sys/`, `net/`, `self/`. Lazily
/// built on first `register`/`proc_reg`. `path == ""` represents `/proc`.
static PROC_REG: Spinlock<Option<Arc<PseudoDir>>, LockClass> = Spinlock::new(None);

/// Get-or-create the `/proc` registry `PseudoDir` (the sys/net/self subtrees).
/// # C: O(1)
pub fn proc_reg() -> Arc<PseudoDir> {
    let mut g = PROC_REG.lock();
    if let Some(r) = g.as_ref() { return Arc::clone(r); }
    let r = PseudoDir::new_root(kernfs::dir_ino("/proc"), PROCFS_FSID);
    *g = Some(Arc::clone(&r));
    r
}

/// Strip the `/proc` mount prefix so `full` becomes root-relative (PROC_REG
/// already represents `/proc`). # C: O(len)
fn rel(full: &str) -> &str {
    full.strip_prefix("/proc/").or_else(|| full.strip_prefix("/proc")).unwrap_or(full)
}

/// Register `full_path` (absolute `/proc/...`) → `inode` in procfs's own
/// sub-tree. Cross-crate writers (drm `/proc/bus/input/devices`) and the
/// boot `register_static_files` call this instead of `devfs::register`.
/// # C: O(depth)
pub fn register(full_path: &str, inode: InodeRef) {
    proc_reg().insert_path(rel(full_path), inode);
}
