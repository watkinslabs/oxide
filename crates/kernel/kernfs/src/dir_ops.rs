use vfs::{DirContext, FileAttr, FileOps, Inode, InodeOps, InodeRef, KResult, VfsError};

use crate::tree::PseudoDir;

/// Which `i_op->fileattr_{get,set}` surface a pseudo-directory publishes. The
/// choice belongs to the OWNING filesystem — it is part of the inode-op vector
/// that filesystem installs — so it rides on the tree root and is inherited by
/// every directory beneath it. No second registry, no per-directory override.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DirFileattr {
    /// Pseudo-filesystem default: no fileattr vector at all, so the ABI edge
    /// reports `EOPNOTSUPP`. sysfs/procfs/tracefs/devpts/cgroup/… sit here.
    Absent,
    /// shmem-backed mount: the same chattr surface a tmpfs directory answers.
    /// The device filesystem's directory tree is such a mount.
    Shmem,
}

pub struct PseudoDirOps {
    fileattr: DirFileattr,
}

impl PseudoDirOps {
    /// Inode-op vector for a pseudo-directory publishing `fileattr`. # C: O(1)
    pub const fn new(fileattr: DirFileattr) -> Self { Self { fileattr } }
}

fn pdir(inode: &Inode) -> KResult<&PseudoDir> {
    inode.private::<PseudoDir>().ok_or(VfsError::Einval)
}

impl InodeOps for PseudoDirOps {
    /// An absent vector answers `Enotty` — the same value the trait default
    /// produces — which the ABI edge renders as `EOPNOTSUPP`. # C: O(1)
    fn fileattr_get(&self, inode: &Inode) -> KResult<FileAttr> {
        match self.fileattr {
            DirFileattr::Absent => Err(VfsError::Enotty),
            DirFileattr::Shmem => vfs::inode::shmem_fileattr_get(inode),
        }
    }

    /// Set half of [`PseudoDirOps::fileattr_get`]. # C: O(1)
    fn fileattr_set(&self, inode: &Inode, fa: &FileAttr) -> KResult<()> {
        match self.fileattr {
            DirFileattr::Absent => Err(VfsError::Enotty),
            DirFileattr::Shmem => vfs::inode::shmem_fileattr_set(inode, fa),
        }
    }

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
