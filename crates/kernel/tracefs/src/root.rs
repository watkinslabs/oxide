//! tracefs (`/sys/kernel/tracing`) + debugfs (`/sys/kernel/debug`) + configfs
//! (`/sys/kernel/config`) OWN
//! `kernfs::PseudoDir` roots (D1c). Replaces reading the subtree back out of
//! the shared devfs registry. Each `root()` returns its tree; content is
//! inserted root-relative (the `/sys/kernel/{tracing,debug,config}` prefix dropped).
//! `overlay = false` — no on-disk backing.

use alloc::sync::Arc;
use kernfs::PseudoDir;
use sync::{Spinlock, TaskList as LockClass};
use vfs::InodeRef;

/// TRACEFS identity for `st_dev`.
pub const TRACEFS_FSID: u64 = 0x0102_1994_0000_0006;
/// DEBUGFS identity for `st_dev`.
pub const DEBUGFS_FSID: u64 = 0x0102_1994_0000_0004;
/// CONFIGFS identity for `st_dev`.
pub const CONFIGFS_FSID: u64 = 0x0102_1994_0000_0005;

#[cfg(test)]
mod tests {
    #[test]
    fn tracefs_identity_is_not_the_procfs_identity() {
        assert_eq!(super::TRACEFS_FSID, 0x0102_1994_0000_0006);
        assert_ne!(super::TRACEFS_FSID, 0x0102_1994_0000_0003);
    }
}

static TRACE_ROOT: Spinlock<Option<Arc<PseudoDir>>, LockClass> = Spinlock::new(None);
static DEBUG_ROOT: Spinlock<Option<Arc<PseudoDir>>, LockClass> = Spinlock::new(None);
static CONFIG_ROOT: Spinlock<Option<Arc<PseudoDir>>, LockClass> = Spinlock::new(None);

/// Get-or-create the `/sys/kernel/tracing` root. # C: O(1)
pub fn trace_root() -> Arc<PseudoDir> {
    let mut g = TRACE_ROOT.lock();
    if let Some(r) = g.as_ref() { return Arc::clone(r); }
    let r = PseudoDir::new_root(kernfs::dir_ino("/sys/kernel/tracing"), TRACEFS_FSID);
    *g = Some(Arc::clone(&r));
    r
}

/// Get-or-create the `/sys/kernel/debug` root. # C: O(1)
pub fn debug_root() -> Arc<PseudoDir> {
    let mut g = DEBUG_ROOT.lock();
    if let Some(r) = g.as_ref() { return Arc::clone(r); }
    let r = PseudoDir::new_root(kernfs::dir_ino("/sys/kernel/debug"), DEBUGFS_FSID);
    *g = Some(Arc::clone(&r));
    r
}

/// Get-or-create the `/sys/kernel/config` root. # C: O(1)
pub fn config_root() -> Arc<PseudoDir> {
    let mut g = CONFIG_ROOT.lock();
    if let Some(r) = g.as_ref() { return Arc::clone(r); }
    let r = PseudoDir::new_root(kernfs::dir_ino("/sys/kernel/config"), CONFIGFS_FSID);
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

/// Insert a debugfs file given its absolute `/sys/kernel/debug/...` path. # C: O(depth)
pub fn register_debug(full_path: &str, inode: InodeRef) {
    let rel = full_path
        .strip_prefix("/sys/kernel/debug/")
        .or_else(|| full_path.strip_prefix("/sys/kernel/debug"))
        .unwrap_or(full_path);
    debug_root().insert_path(rel, inode);
}

/// Insert a configfs file given its absolute `/sys/kernel/config/...` path. # C: O(depth)
pub fn register_config(full_path: &str, inode: InodeRef) {
    let rel = full_path
        .strip_prefix("/sys/kernel/config/")
        .or_else(|| full_path.strip_prefix("/sys/kernel/config"))
        .unwrap_or(full_path);
    config_root().insert_path(rel, inode);
}
