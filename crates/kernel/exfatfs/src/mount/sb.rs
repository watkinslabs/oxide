//! `statfs`, the option tail, and flushing at unmount.

use alloc::string::String;
use alloc::sync::Arc;

use vfs::superblock::{SbStatFs, SuperOps};
use vfs::KResult;

use super::{errno_to_vfs, ExfatFs};

/// The superblock operations of one mounted volume.
pub struct ExfatSuperOps {
    pub(crate) fs: Arc<ExfatFs>,
}

impl SuperOps for ExfatSuperOps {
    /// The unit is the CLUSTER, not the sector: it is what an allocation hands
    /// out, so it is the unit in which a volume is full.
    ///
    /// The free count needs no scan here. exFAT keeps a bitmap, which is read
    /// whole at mount and maintained by every allocation and release, so the
    /// answer is already in memory — where FAT has to walk its table.
    fn statfs(&self) -> KResult<SbStatFs> {
        let v = self.fs.volume.lock();
        let space = v.space();
        Ok(SbStatFs {
            f_type: crate::uapi::EXFAT_SUPER_MAGIC,
            f_bsize: u32::try_from(space.cluster_bytes).unwrap_or(u32::MAX),
            f_blocks: space.total,
            f_bfree: space.free,
            // Nothing is reserved for a privileged caller, so what is free is
            // what is available.
            f_bavail: space.free,
            // A filesystem with no inode table has no inode count to report,
            // and the reference leaves both at zero rather than inventing one.
            f_files: 0,
            f_ffree: 0,
            f_fsid: u64::from(v.geometry().serial),
            f_flags: 0,
            f_namelen: space.name_max,
            f_frsize: 0,
        })
    }

    fn show_options(&self) -> String { crate::opts::show(self.fs.volume.lock().options()) }

    /// Push the in-use percentage.
    ///
    /// The table and the bitmap need no flush of their own: every entry and
    /// every bit is written through to the medium at the moment it changes,
    /// because a volume whose bitmap lags its directories hands out clusters a
    /// file is using.
    fn sync_fs(&self, _wait: bool) -> KResult<()> {
        let mut v = self.fs.volume.lock();
        if !v.writable() { return Ok(()); }
        v.flush_percent_in_use().map_err(errno_to_vfs)
    }
}
