use alloc::sync::Weak;

use super::{Mount, MountError};

impl Mount {
    /// Back-stamp the owning VFS superblock for quota accounting. # C: O(1)
    pub fn set_vfs_superblock(&self, sb: Weak<vfs::SuperBlock>) {
        *self.quota_sb.lock() = sb;
    }

    pub(crate) fn vfs_superblock(&self) -> Option<alloc::sync::Arc<vfs::SuperBlock>> {
        self.quota_sb.lock().upgrade()
    }

    /// Charge/release quota for an exact on-disk i_blocks delta. # C: O(MAXQUOTAS log N)+FS
    pub(crate) fn account_i_blocks_delta(&self, ino: u32, old_sectors: u32, new_sectors: u32) -> Result<(), MountError> {
        if old_sectors == new_sectors { return Ok(()); }
        if self.sb.is_quota_inode(ino) { return Ok(()); }
        let Some(sb) = self.quota_sb.lock().upgrade() else { return Ok(()); };
        if crate::quota::is_active_quota_file(&sb, ino) { return Ok(()); }
        let raw = self.read_inode(ino)?;
        let usage = vfs::DquotUsage {
            space: old_sectors.abs_diff(new_sectors) as u64 * 512,
            reserved_space: 0,
            inodes: 0,
        };
        if new_sectors > old_sectors {
            vfs::dquot_charge_usage(&sb, raw.uid, raw.gid, raw.i_projid, usage).map_err(MountError::Quota)
        } else {
            vfs::dquot_release_usage(&sb, raw.uid, raw.gid, raw.i_projid, usage).map_err(MountError::Quota)
        }
    }

    pub(crate) fn rollback_i_blocks_delta(
        &self, ino: u32, charged_sectors: u32, old_sectors: u32, original: MountError,
    ) -> MountError {
        match self.account_i_blocks_delta(ino, charged_sectors, old_sectors) {
            Ok(()) => original,
            Err(e) => e,
        }
    }
}
