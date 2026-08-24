//! `statfs`, the option tail, and the dirty flag at unmount.

use alloc::string::String;
use alloc::sync::Arc;

use vfs::superblock::{SbStatFs, SuperOps};
use vfs::KResult;

use super::NtfsFs;

/// The superblock operations of one mounted volume.
pub struct NtfsSuperOps {
    pub(crate) fs: Arc<NtfsFs>,
}

impl SuperOps for NtfsSuperOps {
    /// The unit is the CLUSTER, and the inode counts are REAL: unlike FAT and
    /// exFAT, this filesystem has a record table with a count and a bitmap
    /// saying how much of it is used.
    fn statfs(&self) -> KResult<SbStatFs> {
        let v = self.fs.volume.lock();
        let space = v.space();
        Ok(SbStatFs {
            f_type: crate::uapi::NTFS_SUPER_MAGIC,
            f_bsize: u32::try_from(space.cluster_bytes).unwrap_or(u32::MAX),
            f_blocks: space.total,
            f_bfree: space.free,
            f_bavail: space.free,
            f_files: space.records,
            f_ffree: space.records_free,
            f_fsid: v.geometry().serial,
            f_flags: 0,
            f_namelen: space.name_max,
            f_frsize: 0,
        })
    }

    fn show_options(&self) -> String { crate::opts::show(self.fs.volume.lock().options()) }

    /// Every record and every bitmap byte is written through at the moment it
    /// changes, so there is nothing held back to push. What remains is the
    /// dirty flag, which only unmount clears.
    fn sync_fs(&self, _wait: bool) -> KResult<()> {
        let v = self.fs.volume.lock();
        if !v.writable() { return Ok(()); }
        v.update_mft_mirror().map_err(super::errno_to_vfs)
    }

    /// The reports this mount published describe a volume that is about to be
    /// unreachable, so they go with it. The trees hosting them cannot be named
    /// from here, which is why the withdrawal was left behind at mount.
    fn put_super(&self) {
        let _ = self.fs.mark_clean();
        crate::fsattr::run_teardown(&crate::procfs::mount_dir(self.fs.source()));
    }
}
