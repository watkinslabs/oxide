// Delete-side gates: the sticky-directory restriction and `may_delete`, the
// single place unlink / rmdir / rename-overwrite ask "may this name go away".

use alloc::sync::Arc;
use crate::dentry::Dentry;
use crate::inode::InodeRef;
use crate::types::{FileType, KResult, VfsError};

use super::{Cred, MAY_EXEC, MAY_WRITE};
use super::may_create::id_representable;
use super::permission::inode_permission;

/// `check_sticky` (Linux `fs/namei.c`) — restricted-deletion test for a child
/// in a sticky (`S_ISVTX`) directory. Returns `true` when the deletion is
/// FORBIDDEN: the parent `dir` carries the sticky bit AND the caller neither
/// owns the victim (`fsuid == victim.uid`) nor owns the directory
/// (`fsuid == dir.uid`) nor holds CAP_FOWNER (`capable_wrt_inode_uidgid`).
/// A directory with no per-fs perm info (`perm() == None`: pseudo-fs) is never
/// sticky, so deletion is allowed. # C: O(1)
fn check_sticky(dir: &InodeRef, victim: &InodeRef, cred: &Cred) -> bool {
    let Some(dmode) = dir.perm() else { return false; };
    if dmode & crate::types::S_ISVTX == 0 { return false; }
    let fsuid = cred.uid;
    if victim.uid().unwrap_or(0) == fsuid { return false; }
    if dir.uid().unwrap_or(0) == fsuid { return false; }
    !cred.cap_fowner
}

/// `may_delete` (Linux `fs/namei.c` `may_delete_dentry`) — DAC + restriction
/// gate for removing the child `victim` (an existing entry) from directory
/// `dir` via unlink/rmdir/rename-overwrite. Ordering mirrors Linux exactly,
/// because several of these are reachable at once and only the FIRST is
/// reported:
///   1. a victim whose owner the filesystem cannot represent is `EOVERFLOW` —
///      removing a name rewrites the inode, and writing back an unknown owner
///      would corrupt it. This precedes even the permission check;
///   2. write + search (`MAY_WRITE | MAY_EXEC`) on the parent `dir`;
///   3. an append-only parent (`S_APPEND` in `dir.i_flags`) forbids removal;
///   4. the sticky-dir owner-match (`check_sticky`), or an append-only /
///      immutable / swap-backing `victim`, is `EPERM`. Swap membership matters
///      because the swap code holds the victim's block map: dropping its last
///      name would let the blocks be reused under the running swap device;
///   5. type agreement — `isdir` requires the victim be a directory (else
///      `ENOTDIR`); a non-`isdir` delete of a directory is `EISDIR`;
///   6. a directory victim that is its own filesystem's root has no name to
///      remove in this parent — `EBUSY`;
///   7. a parent that is itself already DEAD reports `ENOENT`: the name cannot
///      still be there.
/// `isdir` is the caller's intent (rmdir / `AT_REMOVEDIR` → `true`, unlink →
/// `false`); `victim_is_fs_root` is Linux's `IS_ROOT(victim)`. # C: O(ngroups)
fn may_delete_inner(
    dir: &InodeRef, victim: &InodeRef, isdir: bool, victim_is_fs_root: bool, cred: &Cred,
) -> KResult<()> {
    if !id_representable(victim.uid().unwrap_or(0))
        || !id_representable(victim.gid().unwrap_or(0)) {
        return Err(VfsError::Eoverflow);
    }
    inode_permission(dir, MAY_WRITE | MAY_EXEC, cred)?;
    if dir.i_flags() & crate::inode::S_APPEND != 0 { return Err(VfsError::Eperm); }
    const VICTIM_LOCKED: u32 =
        crate::inode::S_APPEND | crate::inode::S_IMMUTABLE | crate::inode::S_SWAPFILE;
    if check_sticky(dir, victim, cred) || victim.i_flags() & VICTIM_LOCKED != 0 {
        return Err(VfsError::Eperm);
    }
    let victim_is_dir = matches!(victim.file_type(), FileType::Directory);
    if isdir {
        if !victim_is_dir { return Err(VfsError::Enotdir); }
        if victim_is_fs_root { return Err(VfsError::Ebusy); }
    } else if victim_is_dir {
        return Err(VfsError::Eisdir);
    }
    if dir.i_flags() & crate::inode::S_DEAD != 0 { return Err(VfsError::Enoent); }
    Ok(())
}

/// Inode-level `may_delete` for callers that hold no dentry for the victim
/// (mqueuefs unlink, hosted models). Such a victim is never a filesystem root,
/// so the `IS_ROOT` leg is inert. # C: O(ngroups)
pub fn may_delete(dir: &InodeRef, victim: &InodeRef, isdir: bool, cred: &Cred) -> KResult<()> {
    may_delete_inner(dir, victim, isdir, false, cred)
}

/// Dentry-level `may_delete` — the form every path-based removal uses, since
/// only the dentry can answer "is this the filesystem's own root" and "is this
/// name negative". A negative victim is `ENOENT`. # C: O(ngroups)
pub fn may_delete_dentry(
    dir: &InodeRef, victim: &Arc<Dentry>, isdir: bool, cred: &Cred,
) -> KResult<()> {
    let inode = victim.inode().ok_or(VfsError::Enoent)?;
    may_delete_inner(dir, &inode, isdir, victim.is_root(), cred)
}
