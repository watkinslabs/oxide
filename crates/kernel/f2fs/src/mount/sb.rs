//! `statfs` and the option tail.

use alloc::string::String;
use alloc::sync::Arc;

use vfs::superblock::{SbStatFs, SuperOps};
use vfs::KResult;

use crate::limits::NAME_MAX;
use crate::uapi::F2FS_SUPER_MAGIC;

use super::F2fs;

/// The superblock operations of one mounted volume.
pub struct F2fsSuperOps {
    pub(crate) fs: Arc<F2fs>,
}

impl SuperOps for F2fsSuperOps {
    /// The counts come from the checkpoint the mount already read, which is
    /// the same number this filesystem's own writer maintains. Two counts are
    /// reported because a volume can exhaust either: blocks, or node slots.
    fn statfs(&self) -> KResult<SbStatFs> {
        let v = self.fs.volume.lock();
        let s = v.space();
        let sb = v.super_block();
        // The identifier is the volume's own uuid, folded to the width the
        // interface reports, so two mounts of the same medium agree.
        let fsid = u64::from_le_bytes(sb.uuid[..8].try_into().unwrap_or([0u8; 8]));
        Ok(SbStatFs {
            f_type: F2FS_SUPER_MAGIC,
            f_bsize: s.block_bytes,
            f_blocks: s.total,
            f_bfree: s.free,
            f_bavail: s.avail,
            f_files: s.files,
            f_ffree: s.ffree,
            f_fsid: fsid,
            f_flags: 0,
            f_namelen: NAME_MAX,
            f_frsize: 0,
        })
    }

    fn show_options(&self) -> String { crate::opts::show(self.fs.volume.lock().options()) }

    /// Write a checkpoint.
    ///
    /// Until one is written the medium still describes the state this mount
    /// started from: every out-of-place write is invisible, because nothing
    /// points at the new blocks. A read-only mount has nothing to push and
    /// reports success rather than failing every `sync(2)` on the machine.
    fn sync_fs(&self, _wait: bool) -> KResult<()> {
        self.fs.volume.lock().commit().map_err(super::errno_to_vfs)
    }
}
