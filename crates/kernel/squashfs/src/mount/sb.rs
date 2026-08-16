//! `statfs` and the option tail.

use alloc::string::String;
use alloc::sync::Arc;

use vfs::superblock::{SbStatFs, SuperOps};
use vfs::KResult;

use crate::limits::NAME_LEN;

use super::SquashFs;

/// The superblock operations of one mounted image.
pub struct SquashSuperOps {
    pub(crate) fs: Arc<SquashFs>,
}

impl SuperOps for SquashSuperOps {
    /// Nothing is free and nothing is available: the image is exactly as large
    /// as it is, and reporting a free count would tell a caller it could write
    /// where no write can land.
    fn statfs(&self) -> KResult<SbStatFs> {
        let v = self.fs.volume.lock();
        let sb = v.superblock();
        Ok(SbStatFs {
            f_type: crate::uapi::SQUASHFS_SUPER_MAGIC,
            f_bsize: sb.block_size,
            f_blocks: (sb.bytes_used - 1) >> sb.block_log | 1,
            f_bfree: 0,
            f_bavail: 0,
            f_files: u64::from(sb.inodes),
            f_ffree: 0,
            // The image records no identifier of its own, so the mount has
            // none to report; inventing one would collide with a real fsid.
            f_fsid: 0,
            f_flags: 0,
            f_namelen: NAME_LEN as u32,
            f_frsize: 0,
        })
    }

    fn show_options(&self) -> String { crate::opts::show(*self.fs.volume.lock().options()) }

    /// Nothing to push: an image nothing writes to has no dirty state.
    fn sync_fs(&self, _wait: bool) -> KResult<()> { Ok(()) }
}
