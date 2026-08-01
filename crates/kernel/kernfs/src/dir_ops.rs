use vfs::{DirContext, FileOps, Inode, InodeOps, InodeRef, KResult, VfsError};

use crate::tree::PseudoDir;

pub(crate) struct PseudoDirOps;

fn pdir(inode: &Inode) -> KResult<&PseudoDir> {
    inode.private::<PseudoDir>().ok_or(VfsError::Einval)
}

impl InodeOps for PseudoDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        pdir(inode)?.op_lookup(name)
    }

    /// Linux `kernfs_dops`: every cached child of a pseudo-fs directory carries
    /// the revalidating vector, so a node the tree removed or republished stops
    /// resolving to the previous object. # C: O(1)
    fn child_d_op(&self, _inode: &Inode, _name: &str) -> Option<&'static vfs::dentry::DentryOps> {
        Some(&crate::reval::KERNFS_DENTRY_OPS)
    }

    fn mkdir(&self, inode: &Inode, name: &str, mode: u32, ctx: &vfs::CreateCtx) -> KResult<InodeRef> {
        pdir(inode)?.op_mkdir(name, mode, ctx)
    }

    fn rmdir(&self, inode: &Inode, name: &str) -> KResult<()> {
        pdir(inode)?.op_rmdir(name)
    }

    fn symlink(&self, inode: &Inode, name: &str, target: &[u8], _ctx: &vfs::CreateCtx) -> KResult<()> {
        pdir(inode)?.op_symlink(name, target)
    }

    fn rename(
        &self,
        inode: &Inode,
        old: &str,
        new_dir: &Inode,
        new: &str,
        flags: u32,
        _ctx: &vfs::CreateCtx,
    ) -> KResult<()> {
        pdir(inode)?.op_rename(old, pdir(new_dir)?, new, flags)
    }
}

pub(crate) struct PseudoDirFileOps;

impl FileOps for PseudoDirFileOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        pdir(inode)?.op_readdir(ctx)
    }
}
