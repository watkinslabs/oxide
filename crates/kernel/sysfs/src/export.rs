// sysfs's kernfs file-handle owner: one 64-bit live node identity.

use vfs::export::fid::Fid;
use vfs::export::kernfs_fid::{HANDLE_TYPE_KERNFS, KERNFS_FID_LEN, decode_kernfs_fid,
    encode_kernfs_fid};
use vfs::{Ino, InodeRef, KResult, SbStatFs, SuperBlock};

use crate::{PAGE_SIZE, SYSFS_MAGIC, sys_root};

pub(crate) struct SysfsSuperOps;

impl vfs::SuperOps for SysfsSuperOps {
    /// # C: O(1)
    fn statfs(&self) -> KResult<SbStatFs> {
        Ok(SbStatFs { f_type: SYSFS_MAGIC, f_bsize: PAGE_SIZE, ..Default::default() })
    }

    /// # C: O(1)
    fn export_fid_len(&self, _connectable: bool, _is_dir: bool) -> u32 { KERNFS_FID_LEN }

    /// # C: O(1)
    fn export_encode_fh(&self, inode: &InodeRef, _parent: Option<(Ino, u32)>, buf: &mut [u8])
        -> (u32, i32)
    {
        encode_kernfs_fid(inode.ino(), buf)
    }

    /// # C: O(1)
    fn export_fid_len_for_type(&self, handle_type: i32) -> Option<u32> {
        if handle_type == HANDLE_TYPE_KERNFS { Some(KERNFS_FID_LEN) } else { None }
    }

    /// # C: O(1)
    fn export_decode_fh(&self, bytes: &[u8], handle_type: i32)
        -> Result<Fid, syscall::errno::Errno>
    {
        if handle_type != HANDLE_TYPE_KERNFS { return Err(syscall::errno::Errno::Estale); }
        decode_kernfs_fid(bytes)
    }

    /// Resolve only an identity retained by the one live sysfs kernfs tree.
    /// # C: O(nodes)
    fn fh_to_dentry(&self, _sb: &SuperBlock, ino: Ino, _generation: u32) -> Option<InodeRef> {
        sys_root().find_ino(ino)
    }

    /// # C: O(1)
    fn export_can_decode_fh(&self) -> bool { true }
}

#[cfg(test)]
#[path = "export/tests.rs"]
mod tests;
