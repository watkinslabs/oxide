// Module manifest:
// - backend: ext4 hidden-quota VFS hooks and quota-file qtree IO.
// - cleanup: visible quota-file flag/time cleanup for quota-off.
// - insert: quota-file qtree insertion and record write helpers.
// - scan: quota-file qtree lookup/enumeration helpers.
// - enable: quotactl quota-on path and hidden-inode enable flow.

mod backend;
mod ids;
mod cleanup;
mod delete;
mod enable;
mod format;
mod insert;
mod scan;

pub use enable::{quota_on_ext4, quota_on_hidden, quota_on_hidden_remount};

pub(crate) fn is_active_quota_file(sb: &vfs::SuperBlock, ino: u32) -> bool {
    sb.s_dquot.any_operations()
        .and_then(|ops| backend::ops_as_ext4(ops.as_ref()).map(|ext4| ext4.has_active_file(ino)))
        .unwrap_or(false)
}
