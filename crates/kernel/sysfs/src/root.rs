//! sysfs's OWN `kernfs::PseudoDir` root (D1c). Replaces the shared devfs
//! ROOTS write-bus: every `/sys/*` node is inserted into `SYS_ROOT` and
//! `SysfsFs::root()` returns it, so sysfs owns its tree under its own mount
//! instead of reading its subtree back out of the global devfs registry.
//! `overlay = false` — there is no on-disk `/sys` to merge.

use alloc::sync::Arc;
use kernfs::PseudoDir;
use sync::{Spinlock, TaskList as LockClass};
use vfs::InodeRef;

/// sysfs filesystem identity for stat(2) `st_dev` (distinct from devfs so
/// `/sys` and `/dev` no longer alias the same `st_dev`).
pub const SYSFS_FSID: u64 = 0x0102_1994_0000_0002;

/// The single sysfs tree root (mount root of every `/sys` mount). Lazily
/// built on first `register`/`root()`. `path == ""` represents `/sys`.
static SYS_ROOT: Spinlock<Option<Arc<PseudoDir>>, LockClass> = Spinlock::new(None);

/// Get-or-create the `/sys` root `PseudoDir`. # C: O(1)
pub fn sys_root() -> Arc<PseudoDir> {
    let mut g = SYS_ROOT.lock();
    if let Some(r) = g.as_ref() { return Arc::clone(r); }
    let r = PseudoDir::new_root(kernfs::dir_ino("/sys"), SYSFS_FSID);
    *g = Some(Arc::clone(&r));
    r
}

/// Strip the `/sys` mount prefix so `full` becomes root-relative (SYS_ROOT
/// already represents `/sys`). # C: O(len)
fn rel(full: &str) -> &str {
    full.strip_prefix("/sys/").or_else(|| full.strip_prefix("/sys")).unwrap_or(full)
}

/// Register `full_path` (absolute `/sys/...`) → `inode` in sysfs's own tree.
/// Cross-crate writers (procfs `/sys/kernel/*`) call this instead of
/// `devfs::register`. # C: O(depth)
pub fn register(full_path: &str, inode: InodeRef) {
    sys_root().insert_path(rel(full_path), inode);
}

/// Create an empty `/sys/...` directory chain (mount points without leaves,
/// e.g. `/sys/fs/cgroup`, `/sys/kernel/tracing`). # C: O(components)
pub fn register_dir(full_path: &str) {
    sys_root().ensure_dir_path(rel(full_path));
}
