//! tracefs (`/sys/kernel/tracing`) + debugfs (`/sys/kernel/debug`) OWN
//! `kernfs::PseudoDir` roots (D1c). Replaces reading the subtree back out of
//! the shared devfs registry. Each `root()` returns its tree; content is
//! inserted root-relative (the `/sys/kernel/{tracing,debug}` prefix dropped).
//! `overlay = false` — no on-disk backing.

use alloc::sync::Arc;
use kernfs::PseudoDir;
use sync::{Spinlock, TaskList as LockClass};
use vfs::InodeRef;

/// TRACEFS identity for `st_dev`.
pub const TRACEFS_FSID: u64 = 0x0102_1994_0000_0003;
/// DEBUGFS identity for `st_dev`.
pub const DEBUGFS_FSID: u64 = 0x0102_1994_0000_0004;

static TRACE_ROOT: Spinlock<Option<Arc<PseudoDir>>, LockClass> = Spinlock::new(None);
static DEBUG_ROOT: Spinlock<Option<Arc<PseudoDir>>, LockClass> = Spinlock::new(None);

/// Get-or-create the `/sys/kernel/tracing` root. # C: O(1)
pub fn trace_root() -> Arc<PseudoDir> {
    let mut g = TRACE_ROOT.lock();
    if let Some(r) = g.as_ref() { return Arc::clone(r); }
    let r = PseudoDir::new_root(kernfs::dir_ino("/sys/kernel/tracing"), TRACEFS_FSID, false);
    *g = Some(Arc::clone(&r));
    r
}

/// Get-or-create the `/sys/kernel/debug` root. # C: O(1)
pub fn debug_root() -> Arc<PseudoDir> {
    let mut g = DEBUG_ROOT.lock();
    if let Some(r) = g.as_ref() { return Arc::clone(r); }
    let r = PseudoDir::new_root(kernfs::dir_ino("/sys/kernel/debug"), DEBUGFS_FSID, false);
    *g = Some(Arc::clone(&r));
    r
}

/// Insert a tracefs file given its absolute `/sys/kernel/tracing/...` path
/// (the mount prefix is stripped). # C: O(depth)
pub fn register(full_path: &str, inode: InodeRef) {
    let rel = full_path
        .strip_prefix("/sys/kernel/tracing/")
        .or_else(|| full_path.strip_prefix("/sys/kernel/tracing"))
        .unwrap_or(full_path);
    trace_root().insert_path(rel, inode);
}
