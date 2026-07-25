use crate::idmap::{Idmap, INVALID_ID};
use crate::inode::{
    FileAttr, InodeRef, inode_owner_or_capable, FS_APPEND_FL, FS_CASEFOLD_FL,
    FS_COMMON_FL, FS_DAX_FL,
    FS_IMMUTABLE_FL, FS_NODUMP_FL, FS_NOATIME_FL, FS_PROJINHERIT_FL, FS_SYNC_FL, FS_VERITY_FL,
    FS_XFLAG_APPEND, FS_XFLAG_COWEXTSIZE, FS_XFLAG_DAX, FS_XFLAG_EXTSIZE,
    FS_XFLAG_EXTSZINHERIT, FS_XFLAG_IMMUTABLE, FS_XFLAG_CASEFOLD,
    FS_XFLAG_NOATIME, FS_XFLAG_NODUMP,
    FS_XFLAG_PROJINHERIT, FS_XFLAG_SYNC, FS_XFLAG_VERITY, FS_XFLAG_COMMON,
};
use crate::namei::Cred;
use crate::types::{FileType, KResult, VfsError};
use sync::Spinlock;

pub type FileAttrGetHook = fn(&InodeRef) -> KResult<()>;
pub type FileAttrSetHook = fn(&InodeRef, &FileAttr) -> KResult<()>;
pub type FileAttrNotifyHook = fn(&InodeRef);

#[derive(Copy, Clone)]
struct FileAttrHooks {
    get:    Option<FileAttrGetHook>,
    set:    Option<FileAttrSetHook>,
    notify: Option<FileAttrNotifyHook>,
}

impl FileAttrHooks {
    const fn new() -> Self { Self { get: None, set: None, notify: None } }
}

struct FileAttrHookLock;
impl sync::LockClass for FileAttrHookLock { fn rank() -> u16 { 34 } fn name() -> &'static str { "FileAttrHookLock" } }

static HOOKS: Spinlock<FileAttrHooks, FileAttrHookLock> = Spinlock::new(FileAttrHooks::new());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileAttrSource {
    Flags,
    Fsxattr,
}

/// Install Linux fileattr LSM/fsnotify hooks. # C: O(1)
pub fn set_fileattr_hooks(get: Option<FileAttrGetHook>, set: Option<FileAttrSetHook>, notify: Option<FileAttrNotifyHook>) {
    *HOOKS.lock() = FileAttrHooks { get, set, notify };
}

/// Clear fileattr hooks for hosted tests. # C: O(1)
pub fn clear_fileattr_hooks() {
    *HOOKS.lock() = FileAttrHooks::new();
}

/// Linux `vfs_fileattr_get`: security hook before backend `fileattr_get`. # C: FS-dependent
pub fn fileattr_get(inode: &InodeRef) -> KResult<FileAttr> {
    let h = HOOKS.lock().get;
    if let Some(f) = h { f(inode)?; }
    inode.fileattr_get()
}

/// Linux `vfs_fileattr_set`: prepare, LSM hook, backend set, fsnotify. # C: FS-dependent
pub fn fileattr_set(
    idmap: &Idmap,
    inode: &InodeRef,
    want: FileAttr,
    source: FileAttrSource,
    cred: &Cred,
    cap_linux_immutable: bool,
    in_init_user_ns: bool,
) -> KResult<()> {
    if !inode_owner_or_capable(idmap, inode.as_ref(), cred) { return Err(VfsError::Eperm); }
    let old = fill_xflags(fileattr_get(inode)?);
    let fa = fileattr_prepare_set(idmap, inode, old, want, source, cred,
        cap_linux_immutable, in_init_user_ns)?;
    let h = HOOKS.lock();
    let set = h.set;
    let notify = h.notify;
    drop(h);
    if let Some(f) = set { f(inode, &fa)?; }
    inode.fileattr_set(&fa)?;
    if let Some(f) = notify { f(inode); }
    Ok(())
}

fn fill_xflags(mut fa: FileAttr) -> FileAttr {
    if fa.fsx_xflags == 0 && fa.flags != 0 {
        if fa.flags & FS_SYNC_FL      != 0 { fa.fsx_xflags |= FS_XFLAG_SYNC; }
        if fa.flags & FS_IMMUTABLE_FL != 0 { fa.fsx_xflags |= FS_XFLAG_IMMUTABLE; }
        if fa.flags & FS_APPEND_FL    != 0 { fa.fsx_xflags |= FS_XFLAG_APPEND; }
        if fa.flags & FS_NODUMP_FL    != 0 { fa.fsx_xflags |= FS_XFLAG_NODUMP; }
        if fa.flags & FS_NOATIME_FL   != 0 { fa.fsx_xflags |= FS_XFLAG_NOATIME; }
        if fa.flags & FS_DAX_FL       != 0 { fa.fsx_xflags |= FS_XFLAG_DAX; }
        if fa.flags & FS_PROJINHERIT_FL != 0 { fa.fsx_xflags |= FS_XFLAG_PROJINHERIT; }
        if fa.flags & FS_VERITY_FL    != 0 { fa.fsx_xflags |= FS_XFLAG_VERITY; }
        if fa.flags & FS_CASEFOLD_FL  != 0 { fa.fsx_xflags |= FS_XFLAG_CASEFOLD; }
    }
    fa
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
