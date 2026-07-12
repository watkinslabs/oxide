use crate::idmap::{Idmap, INVALID_ID};
use crate::inode::{
    FileAttr, InodeRef, inode_owner_or_capable, FS_APPEND_FL, FS_COMMON_FL, FS_IMMUTABLE_FL,
    FS_XFLAG_COWEXTSIZE, FS_XFLAG_DAX, FS_XFLAG_EXTSIZE, FS_XFLAG_EXTSZINHERIT,
    FS_XFLAG_PROJINHERIT, FS_XFLAG_COMMON,
};
use crate::namei::Cred;
use crate::types::{FileType, KResult, VfsError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileAttrSource {
    Flags,
    Fsxattr,
}

/// Linux `vfs_fileattr_set` prepare: idmap-aware admission plus old-attr merge. # C: O(ngroups)
pub fn fileattr_prepare_set(
    idmap: &Idmap,
    inode: &InodeRef,
    old: FileAttr,
    mut fa: FileAttr,
    source: FileAttrSource,
    cred: &Cred,
    cap_linux_immutable: bool,
    in_init_user_ns: bool,
) -> KResult<FileAttr> {
    if !inode_owner_or_capable(idmap, inode.as_ref(), cred) { return Err(VfsError::Eperm); }
    match source {
        FileAttrSource::Flags => {
            fa.fsx_xflags |= old.fsx_xflags & !FS_XFLAG_COMMON;
            fa.fsx_extsize = old.fsx_extsize;
            fa.fsx_nextents = old.fsx_nextents;
            fa.fsx_projid = old.fsx_projid;
            fa.fsx_cowextsize = old.fsx_cowextsize;
        }
        FileAttrSource::Fsxattr => {
            fa.flags |= old.flags & !FS_COMMON_FL;
        }
    }
    if (fa.flags ^ old.flags) & (FS_APPEND_FL | FS_IMMUTABLE_FL) != 0 && !cap_linux_immutable {
        return Err(VfsError::Eperm);
    }
    if !in_init_user_ns {
        if old.fsx_projid != fa.fsx_projid { return Err(VfsError::Einval); }
        if (old.fsx_xflags ^ fa.fsx_xflags) & FS_XFLAG_PROJINHERIT != 0 {
            return Err(VfsError::Einval);
        }
    } else if old.fsx_projid != fa.fsx_projid && fa.fsx_projid == INVALID_ID {
        return Err(VfsError::Einval);
    }
    let ft = inode.file_type();
    if fa.fsx_xflags & FS_XFLAG_EXTSIZE != 0 && ft != FileType::Regular {
        return Err(VfsError::Einval);
    }
    if fa.fsx_xflags & FS_XFLAG_EXTSZINHERIT != 0 && ft != FileType::Directory {
        return Err(VfsError::Einval);
    }
    if fa.fsx_xflags & FS_XFLAG_COWEXTSIZE != 0
        && ft != FileType::Regular && ft != FileType::Directory
    {
        return Err(VfsError::Einval);
    }
    if fa.fsx_xflags & FS_XFLAG_DAX != 0
        && ft != FileType::Regular && ft != FileType::Directory
    {
        return Err(VfsError::Einval);
    }
    if fa.fsx_extsize == 0 { fa.fsx_xflags &= !(FS_XFLAG_EXTSIZE | FS_XFLAG_EXTSZINHERIT); }
    if fa.fsx_cowextsize == 0 { fa.fsx_xflags &= !FS_XFLAG_COWEXTSIZE; }
    Ok(fa)
}
