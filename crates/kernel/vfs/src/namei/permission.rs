use crate::inode::InodeRef;
use crate::types::{FileType, KResult, VfsError};

use super::{Cred, MAY_EXEC, MAY_READ, MAY_WRITE, S_ISGID, S_ISUID, S_IXGRP};

/// `generic_permission` (Linux `fs/namei.c`) for the access `mask`.
/// Owner/group/other class selection uses the caller credential snapshot.
/// # C: O(ngroups)
pub fn generic_permission(inode: &crate::inode::Inode, mask: u32, cred: &Cred) -> KResult<()> {
    let Some(mode) = inode.perm() else { return Ok(()); };
    let mode = mode as u32;
    let uid = inode.uid().unwrap_or(0);
    let gid = inode.gid().unwrap_or(0);
    let granted = if cred.uid == uid {
        (mode >> 6) & 0o7
    } else if cred.in_group(gid) {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    };
    if granted & mask == mask { return Ok(()); }
    let is_dir = matches!(inode.file_type(), FileType::Directory);
    // CAP_DAC_OVERRIDE: dirs always; non-dir exec only if some exec bit set.
    if cred.cap_dac_override
        && (is_dir || mask & MAY_EXEC == 0 || (mode & 0o111) != 0) {
        return Ok(());
    }
    // CAP_DAC_READ_SEARCH: read + directory search (not write).
    if cred.cap_dac_read_search && mask & MAY_WRITE == 0 && (is_dir || mask & MAY_EXEC == 0) {
        return Ok(());
    }
    Err(VfsError::Eacces)
}

/// `inode_permission` (Linux `fs/namei.c`) — the VFS entry every permission
/// check routes through. Dispatches to the inode's `i_op->permission` override
/// (`Inode::permission`, default `generic_permission`), so a filesystem with
/// ACLs / custom DAC can intercept WITHOUT every call-site changing.
/// # C: O(ngroups)
pub fn inode_permission(inode: &InodeRef, mask: u32, cred: &Cred) -> KResult<()> {
    inode.permission(mask, cred)
}

/// `may_lookup` (Linux): search permission (MAY_EXEC) on a directory before
/// resolving a component within it. # C: O(1)
pub(crate) fn may_lookup(inode: &InodeRef, cred: &Cred) -> KResult<()> {
    inode_permission(inode, MAY_EXEC, cred)
}

/// `may_open` (Linux `fs/namei.c`): DAC check for opening `inode` with the
/// requested read/write access. A SYMLINK final inode is `ELOOP` — it only
/// reaches `may_open` when `open(O_NOFOLLOW)` (without `O_PATH`) left the
/// trailing symlink unfollowed (Linux `may_open` `case S_IFLNK: return -ELOOP`).
/// Writing to a directory is `EISDIR`; otherwise the requested access classes
/// are checked via `inode_permission` (EACCES on deny). The EROFS-on-RO-mount
/// and O_CREAT parent checks live at the syscall layer (they need the resolved
/// mount + parent inode). A freshly O_CREAT'd file skips this entirely (Linux
/// sets acc_mode=0), as does an O_PATH open. # C: O(ngroups)
pub fn may_open(inode: &InodeRef, want_read: bool, want_write: bool, cred: &Cred) -> KResult<()> {
    match inode.file_type() {
        FileType::Symlink => return Err(VfsError::Eloop),
        FileType::Directory if want_write => return Err(VfsError::Eisdir),
        _ => {}
    }
    let mut mask = 0u32;
    if want_read  { mask |= MAY_READ; }
    if want_write { mask |= MAY_WRITE; }
    if mask == 0 { return Ok(()); }
    inode_permission(inode, mask, cred)
}

/// `may_create` (Linux): a new entry in directory `dir` needs write + search
/// on the parent. Used for the O_CREAT path. # C: O(ngroups)
pub fn may_create(dir: &InodeRef, cred: &Cred) -> KResult<()> {
    inode_permission(dir, MAY_WRITE | MAY_EXEC, cred)
}

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

/// `may_delete` (Linux `fs/namei.c`) — DAC + restriction gate for removing the
/// child `victim` (an existing entry) from directory `dir` via
/// unlink/rmdir/rename-overwrite. Mirrors Linux ordering:
///   1. write + search (`MAY_WRITE | MAY_EXEC`) on the parent `dir`;
///   2. an append-only parent (`S_APPEND` in `dir.i_flags`) forbids removal;
///   3. the sticky-dir owner-match (`check_sticky`), or an append-only / immutable
///      `victim` (`S_APPEND` / `S_IMMUTABLE`), is `EPERM`;
///   4. type agreement — `isdir` requires the victim be a directory (else
///      `ENOTDIR`); a non-`isdir` delete of a directory is `EISDIR`.
/// `isdir` is the caller's intent (rmdir / `AT_REMOVEDIR` → `true`, unlink →
/// `false`). # C: O(ngroups)
pub fn may_delete(dir: &InodeRef, victim: &InodeRef, isdir: bool, cred: &Cred) -> KResult<()> {
    inode_permission(dir, MAY_WRITE | MAY_EXEC, cred)?;
    if dir.i_flags() & crate::inode::S_APPEND != 0 { return Err(VfsError::Eperm); }
    if check_sticky(dir, victim, cred)
        || victim.i_flags() & crate::inode::S_APPEND != 0
        || victim.i_flags() & crate::inode::S_IMMUTABLE != 0
    {
        return Err(VfsError::Eperm);
    }
    let victim_is_dir = matches!(victim.file_type(), FileType::Directory);
    if isdir {
        if !victim_is_dir { return Err(VfsError::Enotdir); }
    } else if victim_is_dir {
        return Err(VfsError::Eisdir);
    }
    Ok(())
}

/// `renameat2(2)` flag bits (Linux `include/uapi/linux/fs.h`). The VFS-crate
/// canonical definitions; the syscall shim reuses these rather than re-deriving
/// the bit values at the ABI boundary.
pub const RENAME_NOREPLACE: u32 = 1 << 0;
pub const RENAME_EXCHANGE:  u32 = 1 << 1;
pub const RENAME_WHITEOUT:  u32 = 1 << 2;

/// `do_renameat2` flag validation (Linux `fs/namei.c`): reject unknown bits and
/// the mutually-exclusive combinations. `RENAME_EXCHANGE` may not be combined
/// with `RENAME_NOREPLACE` or `RENAME_WHITEOUT` (both `EINVAL`). # C: O(1)
pub fn rename_flags_check(flags: u32) -> KResult<()> {
    const VALID: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT;
    if flags & !VALID != 0 { return Err(VfsError::Einval); }
    if flags & RENAME_EXCHANGE != 0 && flags & (RENAME_NOREPLACE | RENAME_WHITEOUT) != 0 {
        return Err(VfsError::Einval);
    }
    Ok(())
}

/// `vfs_rename` permission gate (Linux `fs/namei.c`) — the DAC + type-agreement
/// checks for renaming the existing entry `old_victim` (in `old_dir`) onto a
/// name in `new_dir`, where `new_target` is the entry currently at the
/// destination (`None` if the destination name is free). `same_parent` is
/// whether the two parent directories are the same node. Honours `flags`:
///   * `RENAME_NOREPLACE` — destination must be free (`EEXIST` if occupied);
///   * `RENAME_EXCHANGE` — destination must exist (`ENOENT` if free), and the
///     target's deletion check uses the TARGET's OWN type (a dir may swap with a
///     file), not the source's;
///   * plain / `RENAME_WHITEOUT` — the occupied-target deletion check uses the
///     SOURCE's type, so a directory may only replace a directory (`ENOTDIR`
///     otherwise) and a non-directory only a non-directory (`EISDIR`).
/// Order mirrors Linux: existence (`EEXIST`/`ENOENT`), then `may_delete` on the
/// source, then `may_create` (free dest) or `may_delete` (occupied dest), then —
/// when the parent changes and a directory moves — `MAY_WRITE` on the moved
/// subtree (and, for `RENAME_EXCHANGE` of a directory target, the target) for
/// the `..` flip. # C: O(ngroups)
pub fn may_rename(
    old_dir: &InodeRef,
    old_victim: &InodeRef,
    new_dir: &InodeRef,
    new_target: Option<&InodeRef>,
    flags: u32,
    same_parent: bool,
    cred: &Cred,
) -> KResult<()> {
    let is_exchange = flags & RENAME_EXCHANGE != 0;
    if flags & RENAME_NOREPLACE != 0 && new_target.is_some() {
        return Err(VfsError::Eexist);
    }
    if is_exchange && new_target.is_none() {
        return Err(VfsError::Enoent);
    }
    let is_dir = matches!(old_victim.file_type(), FileType::Directory);
    may_delete(old_dir, old_victim, is_dir, cred)?;
    match new_target {
        None => may_create(new_dir, cred)?,
        Some(t) => {
            // EXCHANGE: target's own type (both survive). Else: source's type,
            // enforcing source/target type agreement (ENOTDIR / EISDIR).
            let victim_isdir = if is_exchange { matches!(t.file_type(), FileType::Directory) } else { is_dir };
            may_delete(new_dir, t, victim_isdir, cred)?;
        }
    }
    // Cross-directory move flips a moved directory's `..` entry, needing write
    // on it (Linux: `inode_permission(old_dentry->d_inode, MAY_WRITE)`).
    if !same_parent {
        if is_dir { inode_permission(old_victim, MAY_WRITE, cred)?; }
        if is_exchange {
            if let Some(t) = new_target {
                if matches!(t.file_type(), FileType::Directory) {
                    inode_permission(t, MAY_WRITE, cred)?;
                }
            }
        }
    }
    Ok(())
}

/// `chmod` ownership check (Linux `setattr_prepare`): the caller must own the
/// inode (`fsuid == i_uid`) or hold CAP_FOWNER, else `EPERM`. Owner is read
/// from the per-fs `uid()` (consistent with `inode_permission`). # C: O(1)
pub fn may_chmod(inode: &InodeRef, cred: &Cred) -> KResult<()> {
    let owner = inode.uid().unwrap_or(0);
    if cred.uid == owner || cred.cap_fowner { Ok(()) } else { Err(VfsError::Eperm) }
}

/// `chown` ownership check (Linux `setattr_prepare` / `chown_common`).
/// `new_uid`/`new_gid` are `None` for the `(uid_t)-1` "leave unchanged"
/// sentinel. Changing the uid requires CAP_CHOWN; changing the gid requires
/// either CAP_CHOWN or (owning the file AND being a member of the target
/// group). `EPERM` otherwise. # C: O(ngroups)
pub fn may_chown(
    inode: &InodeRef,
    new_uid: Option<u32>,
    new_gid: Option<u32>,
    cred: &Cred,
) -> KResult<()> {
    let cur_uid = inode.uid().unwrap_or(0);
    let cur_gid = inode.gid().unwrap_or(0);
    if let Some(nu) = new_uid {
        if nu != cur_uid && !cred.cap_chown { return Err(VfsError::Eperm); }
    }
    if let Some(ng) = new_gid {
        if ng != cur_gid {
            let owner_member = cred.uid == cur_uid && cred.in_group(ng);
            if !owner_member && !cred.cap_chown { return Err(VfsError::Eperm); }
        }
    }
    Ok(())
}

/// Adjust a chmod target `mode`: strip `S_ISGID` when the caller is not in the
/// file's owning group and lacks CAP_FSETID (Linux `setattr_prepare`). Prevents
/// a non-member from setting set-group-ID. # C: O(ngroups)
pub fn chmod_sgid_strip(mode: u16, inode: &InodeRef, cred: &Cred) -> u16 {
    let gid = inode.gid().unwrap_or(0);
    if mode & S_ISGID != 0 && !cred.cap_fsetid && !cred.in_group(gid) {
        mode & !S_ISGID
    } else {
        mode
    }
}

/// New mode after a chown drops the set-user-ID bit and (when group-executable)
/// the set-group-ID bit, for a non-directory (Linux `chown_common` sets
/// `ATTR_KILL_SUID|ATTR_KILL_SGID`). Returns `None` when nothing changes.
/// # C: O(1)
pub fn chown_kill_priv(mode: u16, is_dir: bool) -> Option<u16> {
    if is_dir { return None; }
    let mut m = mode;
    m &= !S_ISUID;
    if m & S_IXGRP != 0 { m &= !S_ISGID; }
    if m != mode { Some(m) } else { None }
}
