#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use vfs::Dentry;

use super::mount_dispatch::dispatch_mount;
use super::registry::ensure_filesystems_registered;

/// # C: O(N_path)
pub(crate) fn mount_fstype_at(source: Option<&str>, fstype: &str, target: &str, target_d: &Arc<Dentry>, parent_hint: Option<u64>, data: &str) -> i64 {
    ensure_filesystems_registered();
    dispatch_mount(source, fstype, target, target_d, parent_hint, data)
}
