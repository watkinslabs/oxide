use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use vfs::{FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, mk_mode};
use vfs::superblock::SuperBlock;

use super::inode::{fsid_of, iget_or_build};

pub struct TmpfsSymlinkData { target: Vec<u8> }

/// `i_op` for a tmpfs symlink: `readlink` returns the stored target. # C: O(1)
struct TmpfsSymlinkOps;
impl InodeOps for TmpfsSymlinkOps {
    /// `shmem_fileattr_get` — the `chattr` word for this inode. # C: O(1)
    fn fileattr_get(&self, inode: &Inode) -> KResult<vfs::FileAttr> {
        super::fileattr::tmpfs_fileattr_get(inode)
    }
    /// `shmem_fileattr_set`. # C: O(1)
    fn fileattr_set(&self, inode: &Inode, fa: &vfs::FileAttr) -> KResult<()> {
        super::fileattr::tmpfs_fileattr_set(inode, fa)
    }

    fn readlink(&self, inode: &Inode) -> KResult<Vec<u8>> {
        let d = inode.private::<TmpfsSymlinkData>().ok_or(VfsError::Einval)?;
        Ok(d.target.clone())
    }
}

/// Build a tmpfs symlink inode pointing at `target`, owned by `sb`. # C: O(1)
pub(super) fn make_tmpfs_symlink_inode(target: &[u8], uid: u32, gid: u32, sb: Weak<SuperBlock>, acct: &super::accounting::TmpfsSb) -> InodeRef {
    let ino = acct.alloc_ino();
    let sb2 = sb.clone();
    let target = target.to_vec();
    iget_or_build(&sb, ino, move || {
        let mut b = InodeBuilder::new(ino, mk_mode(FileType::Symlink, 0o777),
            Arc::new(TmpfsSymlinkOps), vfs::default_file_ops())
            .owner(uid, gid)
            .btime(super::birth_time())
            .size(target.len() as u64)
            .fsid(fsid_of(&sb2))
            .xattrs(vfs::SimpleXattrs::new())
            .private(Arc::new(TmpfsSymlinkData { target }));
        if let Some(s) = sb2.upgrade() { b = b.sb(Arc::downgrade(&s)); }
        b.build()
    })
}
