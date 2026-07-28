// `i_op->fileattr_{get,set}` for tmpfs — Linux `mm/shmem.c`
// `shmem_fileattr_get` / `shmem_fileattr_set` / `shmem_set_inode_flags`.
// Reached by `FS_IOC_{GET,SET}FLAGS`, `FS_IOC_FS{GET,SET}XATTR` (slot 16) and
// by `file_getattr(2)` / `file_setattr(2)` (slots 468/469). Without it every
// tmpfs mount — `/tmp`, `/run`, `/dev/shm` — answered `EOPNOTSUPP` where Linux
// answers `0`, and `chattr +i` on a tmpfs file was impossible.
//
// STORAGE: the inode's own `i_flags` word (`vfs::FileAttr::from_i_flags` is the
// reverse map). Linux parks the chattr word in `shmem_inode_info.fsflags`
// because its `inode->i_flags` has no `NODUMP` bit; the oxide inode carries
// `S_NODUMP` itself, so there is no second copy to drift.

use vfs::inode::{FS_APPEND_FL, FS_CASEFOLD_FL, FS_IMMUTABLE_FL, FS_NOATIME_FL, FS_NODUMP_FL,
                 FS_XFLAG_COMMON, S_APPEND, S_CASEFOLD, S_IMMUTABLE, S_NOATIME, S_NODUMP};
use vfs::{FileAttr, FileType, Inode, KResult, VfsError};

/// `SHMEM_FL_USER_MODIFIABLE` (`include/linux/shmem_fs.h`) — everything
/// `shmem_fileattr_set` will accept; any other bit is `EOPNOTSUPP`.
const SHMEM_FL_USER_MODIFIABLE: u32 =
    FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL | FS_NOATIME_FL | FS_CASEFOLD_FL;

/// `fileattr_has_fsx` (`include/linux/fileattr.h`): the request carries
/// `fsxattr`-only state tmpfs cannot store. `fsx_valid` is not part of the
/// `i_op` signature here; it is implied, because `vfs::fileattr_set` fills the
/// `fsx_*` fields from the CURRENT attrs on the `FS_IOC_SETFLAGS` path, and
/// tmpfs's current attrs never carry any. # C: O(1)
fn has_fsx(fa: &FileAttr) -> bool {
    fa.fsx_xflags & !FS_XFLAG_COMMON != 0 || fa.fsx_extsize != 0 || fa.fsx_projid != 0
        || fa.fsx_cowextsize != 0
}

/// `shmem_inode_casefold_flags`: turning `FS_CASEFOLD_FL` ON needs a
/// casefolding superblock (`sb->s_encoding`). tmpfs here has no encoding, so
/// the answer is `EOPNOTSUPP` unless the bit is already set. # C: O(1)
fn casefold_ok(old_i_flags: u32, want: u32) -> KResult<()> {
    if want & FS_CASEFOLD_FL != 0 && old_i_flags & S_CASEFOLD == 0 {
        return Err(VfsError::Eopnotsupp);
    }
    Ok(())
}

/// `shmem_fileattr_get`. # C: O(1)
pub(super) fn tmpfs_fileattr_get(inode: &Inode) -> KResult<FileAttr> {
    Ok(vfs::fileattr_fill_flags(FileAttr::from_i_flags(inode.i_flags()).flags))
}

/// `shmem_fileattr_set`: reject fsxattr-only state and unmodifiable bits, then
/// merge the modifiable set into `i_flags` and stamp ctime + i_version.
/// # C: O(1)
pub(super) fn tmpfs_fileattr_set(inode: &Inode, fa: &FileAttr) -> KResult<()> {
    if has_fsx(fa) { return Err(VfsError::Eopnotsupp); }
    if fa.flags & !SHMEM_FL_USER_MODIFIABLE != 0 { return Err(VfsError::Eopnotsupp); }
    let old = inode.i_flags();
    casefold_ok(old, fa.flags)?;
    // `shmem_inode_casefold_flags`: a casefold change on a directory is only
    // legal while it is empty; oxide never turns the bit ON (no encoding), so
    // only the CLEAR direction can reach here, and only for a directory.
    if fa.flags & FS_CASEFOLD_FL == 0 && old & S_CASEFOLD != 0
        && inode.file_type() != FileType::Directory
    {
        return Err(VfsError::Enotdir);
    }
    let mut s = old & !(S_IMMUTABLE | S_APPEND | S_NOATIME | S_NODUMP | S_CASEFOLD);
    if fa.flags & FS_IMMUTABLE_FL != 0 { s |= S_IMMUTABLE; }
    if fa.flags & FS_APPEND_FL    != 0 { s |= S_APPEND; }
    if fa.flags & FS_NOATIME_FL   != 0 { s |= S_NOATIME; }
    if fa.flags & FS_NODUMP_FL    != 0 { s |= S_NODUMP; }
    if fa.flags & FS_CASEFOLD_FL  != 0 { s |= S_CASEFOLD; }
    inode.set_i_flags(s);
    let raw_now = vfs::inode_times::realtime_now_ns();
    let ctime_ns = vfs::inode_times::current_time(inode, raw_now);
    vfs::inode::inode_inc_iversion(inode);
    inode.set_times(None, None, ctime_ns)?;
    Ok(())
}
