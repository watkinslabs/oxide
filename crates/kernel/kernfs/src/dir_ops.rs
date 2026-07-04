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

    fn mkdir(&self, inode: &Inode, name: &str, _mode: u32, _ctx: &vfs::CreateCtx) -> KResult<InodeRef> {
        pdir(inode)?.op_mkdir(name)
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
        let off = ctx.pos;
        pdir(inode)?.op_readdir(off, &mut |ino, next, name, ft| ctx.emit(name, ino, ft, next))?;
        Ok(())
    }
}
