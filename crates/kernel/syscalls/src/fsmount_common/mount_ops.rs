#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use vfs::Dentry;

use super::mount_dispatch::dispatch_mount;
use super::registry::ensure_filesystems_registered;

/// `ms_flags` is the raw `mount(2)` flag word; the per-mount MNT_* option mask is
/// derived from it at the graft (`dispatch_mount`). # C: O(N_path)
pub(crate) fn mount_fstype_at(source: Option<&str>, fstype: &str, target: &str, target_d: &Arc<Dentry>,
    parent_hint: Option<u64>, data: &str, ms_flags: u64) -> i64 {
    ensure_filesystems_registered();
    dispatch_mount(source, fstype, target, target_d, parent_hint, data, ms_flags,
        crate::mount_perm::sample_mount_caps())
}
