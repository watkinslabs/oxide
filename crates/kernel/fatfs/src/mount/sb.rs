//! `statfs`, the option tail, and flushing at unmount.
//!
//! `statfs` is the one caller of the free-cluster count, and the count is why
//! this exists at all: FAT keeps no free-space accounting beyond the FAT32
//! information sector's hint, so the only authoritative answer is a scan of
//! the whole table. It is taken ONCE, on the first question that needs it, and
//! maintained by every allocation and release from then on — which is what
//! makes `df` on a freshly mounted volume cost a table walk and every later
//! one cost nothing.

use alloc::string::String;
use alloc::sync::Arc;

use vfs::superblock::{SbStatFs, SuperOps};
use vfs::KResult;

use super::{errno_to_vfs, FatFs, MSDOS_SUPER_MAGIC};

/// The superblock operations of one mounted volume.
pub struct FatSuperOps {
    pub(crate) fs: Arc<FatFs>,
}

impl SuperOps for FatSuperOps {
    /// The unit is the CLUSTER, not the sector: it is what an allocation
    /// hands out, so it is the unit in which a volume is full.
    fn statfs(&self) -> KResult<SbStatFs> {
        let mut v = self.fs.volume.lock();
        let free = u64::from(v.free_clusters_counted());
        let opts = *v.options();
        Ok(SbStatFs {
            f_type: MSDOS_SUPER_MAGIC,
            f_bsize: u32::try_from(v.geometry().cluster_bytes()).unwrap_or(u32::MAX),
            f_blocks: u64::from(v.total_clusters()),
            f_bfree: free,
            // FAT reserves nothing for a privileged caller, so what is free is
            // what is available.
            f_bavail: free,
            // A filesystem with no inode table has no inode count to report,
            // and the reference leaves both at zero rather than inventing one.
            f_files: 0,
            f_ffree: 0,
            f_fsid: 0,
            f_flags: 0,
            f_namelen: opts.name_max(),
            f_frsize: 0,
        })
    }

    fn show_options(&self) -> String { crate::opts::show(self.fs.volume.lock().options()) }

    /// Push the table, the information sector and the dirty flag.
    ///
    /// The table goes first: the information sector's count describes it, and
    /// a count written ahead of the table it counts describes a state that was
    /// never on the medium.
    fn sync_fs(&self, _wait: bool) -> KResult<()> {
        let mut v = self.fs.volume.lock();
        if !v.writable() { return Ok(()); }
        v.flush_table().map_err(errno_to_vfs)?;
        v.flush_fsinfo().map_err(errno_to_vfs)
    }
}
