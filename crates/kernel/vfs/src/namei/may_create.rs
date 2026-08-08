// Create-side gates: `may_create` (a new name in a directory) and the
// sticky-directory `O_CREAT`-onto-existing restriction.

use crate::inode::InodeRef;
use crate::types::{FileType, KResult, VfsError};

use super::{Cred, MAY_EXEC, MAY_WRITE};
use super::permission::inode_permission;

/// `may_create` (`may_create_dentry`) — the gate for adding
/// a new name to directory `dir`. The caller owns the `EEXIST` half (read
/// off the child dentry it already holds); this is the rest, in the
/// reference order:
///   1. a DEAD directory — one whose last name was already removed by `rmdir`,
///      so it can never gain another child — is `ENOENT`, not `EACCES`. This
///      stands AHEAD of the DAC check, so a writable-but-doomed directory
///      reports the doom, not permission;
///   2. an unrepresentable caller identity is `EOVERFLOW` (writing back an
///      inode whose owner the filesystem cannot express would corrupt it);
///   3. write + search (`MAY_WRITE | MAY_EXEC`) on the parent.
/// # C: O(ngroups)
pub fn may_create(dir: &InodeRef, cred: &Cred) -> KResult<()> {
    if dir.i_flags() & crate::inode::S_DEAD != 0 { return Err(VfsError::Enoent); }
    if !id_representable(cred.uid) || !id_representable(cred.gid) {
        return Err(VfsError::Eoverflow);
    }
    inode_permission(dir, MAY_WRITE | MAY_EXEC, cred)
}

/// `(uid_t)-1` is the reserved "no such id" sentinel: an inode carrying it
/// cannot be written back correctly, and a caller holding it cannot own a new
/// object. The reference predicate pair is `vfsuid_valid`/`vfsgid_valid`. # C: O(1)
pub(super) fn id_representable(id: u32) -> bool { id != u32::MAX }

const PROTECTED_FIFOS: u8 = 1;
const PROTECTED_REGULAR: u8 = 2;

/// `may_create_in_sticky`: an `O_CREAT` open of an entry
/// that already exists in a sticky directory is denied unless the existing
/// inode is owned by the caller or by the directory owner. The sysctl defaults
/// match this tree's `/proc/sys/fs/protected_{fifos,regular}` leaves. # C: O(1)
pub fn may_create_in_sticky(dir: &InodeRef, inode: &InodeRef, cred: &Cred) -> KResult<()> {
    let Some(dir_mode) = dir.perm() else { return Ok(()); };
    if dir_mode & crate::types::S_ISVTX == 0 { return Ok(()); }
    let ft = inode.file_type();
    if ft == FileType::Regular && PROTECTED_REGULAR == 0 { return Ok(()); }
    if ft == FileType::Fifo && PROTECTED_FIFOS == 0 { return Ok(()); }
    let inode_uid = inode.uid().unwrap_or(0);
    if inode_uid == dir.uid().unwrap_or(0) { return Ok(()); }
    if inode_uid == cred.uid { return Ok(()); }
    if dir_mode & 0o002 != 0 { return Err(VfsError::Eacces); }
    if dir_mode & 0o020 != 0 {
        if ft == FileType::Fifo && PROTECTED_FIFOS >= 2 { return Err(VfsError::Eacces); }
        if ft == FileType::Regular && PROTECTED_REGULAR >= 2 { return Err(VfsError::Eacces); }
    }
    Ok(())
}
