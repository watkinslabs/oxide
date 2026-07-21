//! Tmpfs inode-data lifetime pins for in-flight transactions.

use alloc::sync::Arc;

use super::file::TmpfsFileData;

impl TmpfsFileData {
    /// Retain the inode-owned data through one reclaim transaction. # C: O(1)
    pub(super) fn pin_transaction(&self) -> Option<Arc<Self>> {
        self.self_ref.lock().upgrade()
    }
}

/// Emit one retained, explicitly armed migration-owner transition record.
/// # C: O(1)
#[cfg(feature = "debug-zram-lifecycle")]
pub(super) fn trace_migration(event: &'static [u8], data: &TmpfsFileData, idx: u64, token: hal::pt_walker::MigrationEntry) {
    klog::write_raw(b"[TMPFS-MIG ");
    klog::write_raw(event);
    klog::write_raw(b" owner=");
    klog::write_hex_u64(data as *const TmpfsFileData as u64);
    klog::write_raw(b" idx=");
    klog::write_hex_u64(idx);
    klog::write_raw(b" token=");
    klog::write_hex_u64(token.token());
    klog::write_raw(b"]\n");
}
