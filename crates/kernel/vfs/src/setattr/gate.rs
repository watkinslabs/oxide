//! `may_setattr` + the `chown_ok` / `chgrp_ok` authorization predicates
//! (Linux `fs/attr.c`), split out of `setattr.rs` so the DAC decision for an
//! attribute change lives in one named place.
//!
//! `may_setattr` is the gate `notify_change` runs BEFORE `setattr_prepare`:
//! an immutable or append-only inode refuses every ownership / mode / explicit
//! timestamp change with `EPERM`, and no capability lifts it. The "set both
//! timestamps to now" form (Linux `ATTR_TOUCH`) is the sole attribute change a
//! non-owner with write access may make, and it still refuses on an immutable
//! inode.

use crate::idmap::{Idmap, INVALID_ID};
use crate::inode::{InodeRef, inode_owner_or_capable};
use crate::inode::{S_APPEND, S_IMMUTABLE};
use crate::namei::{Cred, inode_permission, MAY_WRITE};
use crate::types::{KResult, VfsError};

use super::{ATTR_ATIME, ATTR_ATIME_SET, ATTR_GID, ATTR_MODE, ATTR_MTIME, ATTR_MTIME_SET, ATTR_UID};

/// Linux `ATTR_TOUCH`: `utimes(2)` and friends called with `times == NULL`, or
/// with BOTH times `UTIME_NOW`. Both atime and mtime are selected and neither
/// carries a specific value. This is the only timestamp form a non-owner with
/// mere write permission may perform. # C: O(1)
pub fn attr_touch(valid: u32) -> bool {
    valid & (ATTR_ATIME | ATTR_MTIME) == ATTR_ATIME | ATTR_MTIME
        && valid & (ATTR_ATIME_SET | ATTR_MTIME_SET) == 0
}

/// Linux `ATTR_TIMES_SET | ATTR_ATIME_SET | ATTR_MTIME_SET`: any timestamp
/// change that is NOT "both to now" — a specific instant, or a per-field
/// selection that leaves the other field `UTIME_OMIT`. Owner-or-CAP_FOWNER
/// only, even when the live field's value is "now". # C: O(1)
pub fn attr_times_set(valid: u32) -> bool {
    valid & (ATTR_ATIME | ATTR_MTIME) != 0 && !attr_touch(valid)
}

/// `may_setattr` (Linux `fs/attr.c`) — the gate ahead of `setattr_prepare`.
/// An immutable or append-only inode refuses a mode / owner / explicit-time
/// change outright; an immutable inode additionally refuses the "touch" form,
/// which is otherwise open to any writer. Note a *size* change is deliberately
/// absent from both masks: `truncate`'s append reject and its `MAY_WRITE`
/// requirement (which is what makes an immutable inode refuse) are checked by
/// the truncate path itself. # C: O(ngroups)
pub fn may_setattr(idmap: &Idmap, inode: &InodeRef, valid: u32, cred: &Cred) -> KResult<()> {
    if valid & (ATTR_MODE | ATTR_UID | ATTR_GID) != 0 || attr_times_set(valid) {
        if inode.i_flags() & (S_IMMUTABLE | S_APPEND) != 0 { return Err(VfsError::Eperm); }
    }
    if attr_touch(valid) {
        if inode.i_flags() & S_IMMUTABLE != 0 { return Err(VfsError::Eperm); }
        if !inode_owner_or_capable(idmap, inode.as_ref(), cred) {
            inode_permission(inode, MAY_WRITE, cred)?;
        }
    }
    Ok(())
}

/// `chown_ok` (Linux `fs/attr.c`) — may this caller set the inode's owner to
/// `ia_vfsuid`? The unprivileged clause is NOT "the id is unchanged": it is
/// "the caller IS the owner *and* the target equals the current owner", i.e. a
/// no-op chown by the owner. A stranger naming the file's existing uid is
/// refused, which is the whole point of the rule. Otherwise CAP_CHOWN, which —
/// like every `capable_wrt_inode_uidgid` gate — may not be exercised over an
/// owner with no mapping in the caller's namespace unless the capability is
/// held in the namespace the filesystem itself is mounted from. # C: O(1)
pub fn chown_ok(idmap: &Idmap, inode: &InodeRef, ia_vfsuid: u32, cred: &Cred) -> bool {
    let vfsuid = idmap.map_out_uid(inode.uid().unwrap_or(0));
    if vfsuid == cred.uid && ia_vfsuid == vfsuid { return true; }
    cred.cap_chown
}

/// `chgrp_ok` (Linux `fs/attr.c`) — may this caller set the inode's group to
/// `ia_vfsgid`? The owner may move the file into any group they are a member
/// of, or leave it in the group it is already in; everyone else needs
/// CAP_CHOWN. A non-owner naming the file's existing gid is refused.
/// # C: O(ngroups)
pub fn chgrp_ok(idmap: &Idmap, inode: &InodeRef, ia_vfsgid: u32, cred: &Cred) -> bool {
    let vfsgid = idmap.map_out_gid(inode.gid().unwrap_or(0));
    let vfsuid = idmap.map_out_uid(inode.uid().unwrap_or(0));
    if vfsuid == cred.uid && (ia_vfsgid == vfsgid || cred.in_group(ia_vfsgid)) { return true; }
    cred.cap_chown
}

/// `vfsuid_has_fsmapping` / `vfsgid_has_fsmapping` + the "don't allow
/// modifications of files with invalid uids or gids unless those uids & gids
/// are being made valid" rule (Linux `notify_change`). A target owner the
/// filesystem cannot represent is `EOVERFLOW`, never a silently truncated
/// on-disk owner; and an inode whose EXISTING owner has no mapping in the
/// caller's view refuses every change that does not replace that owner.
/// # C: O(extents)
pub fn check_owner_mappings(idmap: &Idmap, inode: &InodeRef, valid: u32, uid: u32, gid: u32)
    -> KResult<()>
{
    if valid & ATTR_UID != 0 {
        if idmap.map_in_uid(uid) == INVALID_ID { return Err(VfsError::Eoverflow); }
    } else if idmap.map_out_uid(inode.uid().unwrap_or(0)) == INVALID_ID {
        return Err(VfsError::Eoverflow);
    }
    if valid & ATTR_GID != 0 {
        if idmap.map_in_gid(gid) == INVALID_ID { return Err(VfsError::Eoverflow); }
    } else if idmap.map_out_gid(inode.gid().unwrap_or(0)) == INVALID_ID {
        return Err(VfsError::Eoverflow);
    }
    Ok(())
}
