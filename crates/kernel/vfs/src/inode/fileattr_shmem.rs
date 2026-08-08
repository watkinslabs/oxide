// shmem-backed `i_op->fileattr_{get,set}`: the chattr-style flag surface every
// shmem-backed mount exposes — the tmpfs mounts (`/tmp`, `/run`, `/dev/shm`)
// AND the device filesystem's own directory tree, which is a shmem instance in
// the reference. ONE implementation lives here so the two consumers cannot
// drift; there is no per-filesystem copy.
//
// STORAGE: the inode's own `i_flags` word (`FileAttr::from_i_flags` is the
// reverse map) — a single copy, so there is nothing to drift.
//
// Reached by `FS_IOC_{GET,SET}FLAGS`, `FS_IOC_FS{GET,SET}XATTR` (slot 16) and
// by `file_getattr(2)` / `file_setattr(2)` (slots 468/469).

use super::flags::{FS_APPEND_FL, FS_CASEFOLD_FL, FS_IMMUTABLE_FL, FS_NOATIME_FL, FS_NODUMP_FL,
                   FS_XFLAG_CASEFOLD, FS_XFLAG_COMMON, S_APPEND, S_CASEFOLD, S_IMMUTABLE,
                   S_NOATIME, S_NODUMP};
use super::model::{FileAttr, Inode};
use crate::types::{FileType, KResult, VfsError};

/// Every chattr-style bit a shmem `fileattr_set` will accept; any other bit
/// is `EOPNOTSUPP`.
const SHMEM_FL_USER_MODIFIABLE: u32 =
    FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL | FS_NOATIME_FL | FS_CASEFOLD_FL;

/// Whether the request carries `fsxattr`-only state shmem cannot store.
/// `fsx_valid` is not part of the `i_op` signature here; it is implied, because
/// `crate::fileattr::fileattr_set` fills the `fsx_*` fields from the CURRENT
/// attrs on the `FS_IOC_SETFLAGS` path, and shmem's current attrs never carry
/// any. # C: O(1)
fn has_fsx(fa: &FileAttr) -> bool {
    // The casefold xflag is a MIRROR of the chattr bit, filled in from it on
    // the way out, so reading a casefolded directory's attributes and writing
    // them back must not read as fsxattr-only state the backend cannot store.
    const DERIVED: u32 = FS_XFLAG_COMMON | FS_XFLAG_CASEFOLD;
    fa.fsx_xflags & !DERIVED != 0 || fa.fsx_extsize != 0 || fa.fsx_projid != 0
        || fa.fsx_cowextsize != 0
}

/// `shmem_inode_casefold_flags`: turning `FS_CASEFOLD_FL` ON needs an instance
/// that declared a name encoding, a directory to turn it on, and — because
/// every name already in it was hashed by the case-SENSITIVE rule — an empty
/// one. The ladder's order is observable: a regular file on an instance with no
/// encoding reports the missing encoding, not the wrong type.
/// # C: O(1) plus the emptiness probe
fn casefold_ok(inode: &Inode, old_i_flags: u32, want: u32) -> KResult<()> {
    if want & FS_CASEFOLD_FL == 0 || old_i_flags & S_CASEFOLD != 0 { return Ok(()); }
    let has_encoding = inode.i_sb().is_some_and(|sb| sb.s_encoding().is_some());
    if !has_encoding { return Err(VfsError::Eopnotsupp); }
    if inode.file_type() != FileType::Directory { return Err(VfsError::Enotdir); }
    if !inode.i_op().dir_is_empty(inode) { return Err(VfsError::Enotempty); }
    Ok(())
}

/// `shmem_fileattr_get`. # C: O(1)
pub fn shmem_fileattr_get(inode: &Inode) -> KResult<FileAttr> {
    Ok(crate::fileattr::fileattr_fill_flags(FileAttr::from_i_flags(inode.i_flags()).flags))
}

/// `shmem_fileattr_set`: reject fsxattr-only state and unmodifiable bits, then
/// merge the modifiable set into `i_flags` and stamp ctime + i_version.
/// # C: O(1)
pub fn shmem_fileattr_set(inode: &Inode, fa: &FileAttr) -> KResult<()> {
    if has_fsx(fa) { return Err(VfsError::Eopnotsupp); }
    if fa.flags & !SHMEM_FL_USER_MODIFIABLE != 0 { return Err(VfsError::Eopnotsupp); }
    let old = inode.i_flags();
    casefold_ok(inode, old, fa.flags)?;
    // Clearing the bit is equally only legal while the directory is empty: the
    // names inside were hashed by the folded rule and would stop resolving.
    if fa.flags & FS_CASEFOLD_FL == 0 && old & S_CASEFOLD != 0 {
        if inode.file_type() != FileType::Directory { return Err(VfsError::Enotdir); }
        if !inode.i_op().dir_is_empty(inode) { return Err(VfsError::Enotempty); }
    }
    let mut s = old & !(S_IMMUTABLE | S_APPEND | S_NOATIME | S_NODUMP | S_CASEFOLD);
    if fa.flags & FS_IMMUTABLE_FL != 0 { s |= S_IMMUTABLE; }
    if fa.flags & FS_APPEND_FL    != 0 { s |= S_APPEND; }
    if fa.flags & FS_NOATIME_FL   != 0 { s |= S_NOATIME; }
    if fa.flags & FS_NODUMP_FL    != 0 { s |= S_NODUMP; }
    if fa.flags & FS_CASEFOLD_FL  != 0 { s |= S_CASEFOLD; }
    inode.set_i_flags(s);
    let raw_now = crate::inode_times::realtime_now_ns();
    let ctime = crate::inode_times::current_time(inode, raw_now);
    super::helpers::inode_inc_iversion(inode);
    inode.set_times(None, None, ctime)?;
    Ok(())
}
