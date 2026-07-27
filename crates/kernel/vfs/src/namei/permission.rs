use crate::inode::InodeRef;
use crate::types::{FileType, KResult, VfsError};
use core::sync::atomic::Ordering;

use super::{Cred, MAY_EXEC, MAY_READ, MAY_WRITE, S_ISGID, S_ISUID, S_IXGRP};

/// `generic_permission` (Linux `fs/namei.c`) for the access `mask`.
/// Owner/group/other class selection uses the caller credential snapshot.
/// # C: O(ngroups)
pub fn generic_permission(inode: &crate::inode::Inode, mask: u32, cred: &Cred) -> KResult<()> {
    let Some(mode) = inode.perm() else { return Ok(()); };
    let mode = mode as u32;
    let uid = inode.uid().unwrap_or(0);
    let gid = inode.gid().unwrap_or(0);
    let want = mask & (MAY_READ | MAY_WRITE | MAY_EXEC);
    let granted = if cred.uid == uid {
        (mode >> 6) & 0o7
    } else {
        // POSIX ACL (Linux `acl_permission_check` → `check_acl`): a non-owner
        // caller is decided by the access ACL when the inode carries one. The
        // ACL covers named users/groups + a mask + `other`, so it fully replaces
        // the group/other mode-bit selection. Absent an ACL, fall to mode bits.
        match acl_decision(inode, cred, uid, gid, want) {
            Some(true) => return Ok(()),
            Some(false) => 0, // ACL denied — caps below may still override
            None if cred.in_group(gid) => (mode >> 3) & 0o7,
            None => mode & 0o7,
        }
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
    #[cfg(feature = "debug-eacces")]
    {
        // [EACCES] DAC denial: inode identity + owner/mode vs caller creds +
        // requested access mask (r=4/w=2/x=1). Correlate with the [OPENAT] path
        // line logged for the same syscall to pin the exact file + why.
        klog::write_raw(b"[EACCES] ino=");
        klog::write_hex_u64(inode.ino() as u64);
        klog::write_raw(b" i_uid=");
        klog::write_dec_u64(uid as u64);
        klog::write_raw(b" i_gid=");
        klog::write_dec_u64(gid as u64);
        klog::write_raw(b" mode=");
        klog::write_hex_u64((mode & 0o7777) as u64);
        klog::write_raw(b" mask=");
        klog::write_hex_u64(mask as u64);
        klog::write_raw(b" c_uid=");
        klog::write_dec_u64(cred.uid as u64);
        klog::write_raw(b" c_gid=");
        klog::write_dec_u64(cred.gid as u64);
        klog::write_raw(b" dac_ovr=");
        klog::write_dec_u64(cred.cap_dac_override as u64);
        klog::write_raw(b"\n");
    }
    Err(VfsError::Eacces)
}

// POSIX ACL entry tags (`linux/posix_acl.h`).
const ACL_USER_OBJ:  u16 = 0x01;
const ACL_USER:      u16 = 0x02;
const ACL_GROUP_OBJ: u16 = 0x04;
const ACL_GROUP:     u16 = 0x08;
const ACL_MASK:      u16 = 0x10;
const ACL_OTHER:     u16 = 0x20;
const POSIX_ACL_XATTR_VERSION: u32 = 2;

/// Decide access from the inode's `system.posix_acl_access` xattr, Linux
/// `check_acl` → `posix_acl_permission`. `Some(true)`=granted, `Some(false)`=
/// denied by the ACL, `None`=no (usable) ACL so the caller uses mode bits.
/// # C: O(N_acl_entries)
fn acl_decision(inode: &crate::inode::Inode, cred: &Cred, i_uid: u32, i_gid: u32, want: u32) -> Option<bool> {
    let acl = inode.simple_xattrs()?.get("system.posix_acl_access")?;
    posix_acl_permission(&acl, cred, i_uid, i_gid, want)
}

/// Linux `posix_acl_permission`. The on-disk/xattr form is a 4-byte
/// `POSIX_ACL_XATTR_VERSION` header followed by entries of `{tag:u16, perm:u16,
/// id:u32}` (all little-endian), ordered USER_OBJ, USER*, GROUP_OBJ, GROUP*,
/// MASK, OTHER. `want` is the requested r/w/x bits (== ACL perm bits).
/// # C: O(N_entries)
fn posix_acl_permission(buf: &[u8], cred: &Cred, i_uid: u32, i_gid: u32, want: u32) -> Option<bool> {
    if buf.len() < 4 { return None; }
    let ver = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if ver != POSIX_ACL_XATTR_VERSION { return None; }
    let ents = &buf[4..];
    if ents.len() % 8 != 0 || ents.is_empty() { return None; }
    let n = ents.len() / 8;
    let entry = |i: usize| -> (u16, u16, u32) {
        let o = i * 8;
        (u16::from_le_bytes([ents[o], ents[o+1]]),
         u16::from_le_bytes([ents[o+2], ents[o+3]]),
         u32::from_le_bytes([ents[o+4], ents[o+5], ents[o+6], ents[o+7]]))
    };
    // The MASK (if any) limits USER/GROUP_OBJ/GROUP entries.
    let mask_perm = (0..n).find_map(|i| { let (t, p, _) = entry(i); (t == ACL_MASK).then_some(p as u32) });
    let mut found_group = false;
    for i in 0..n {
        let (tag, perm, id) = entry(i);
        let perm = perm as u32;
        match tag {
            ACL_USER_OBJ => {
                if cred.uid == i_uid { return Some(perm & want == want); }
            }
            ACL_USER => {
                if cred.uid == id {
                    let eff = mask_perm.map_or(perm, |m| perm & m);
                    return Some(eff & want == want);
                }
            }
            ACL_GROUP_OBJ => {
                if cred.in_group(i_gid) {
                    found_group = true;
                    let eff = mask_perm.map_or(perm, |m| perm & m);
                    if eff & want == want { return Some(true); }
                }
            }
            ACL_GROUP => {
                if cred.in_group(id) {
                    found_group = true;
                    let eff = mask_perm.map_or(perm, |m| perm & m);
                    if eff & want == want { return Some(true); }
                }
            }
            ACL_MASK => {}
            ACL_OTHER => {
                // Reached `other` without an earlier match: a caller who matched
                // a group class but wasn't granted is DENIED (never falls to
                // `other`); everyone else uses `other`.
                if found_group { return Some(false); }
                return Some(perm & want == want);
            }
            _ => return None,
        }
    }
    None
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

const PROTECTED_FIFOS: u8 = 1;
const PROTECTED_REGULAR: u8 = 2;

/// `may_create_in_sticky` (Linux `fs/namei.c`): an `O_CREAT` open of an entry
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

const PROTECTED_HARDLINKS: bool = true;

/// Linux `safe_hardlink_source`: non-owner hardlinks are only safe for regular
/// files that are not setuid, not executable-setgid, and readable+writable by
/// the caller. # C: O(ngroups)
fn safe_hardlink_source(inode: &InodeRef, cred: &Cred) -> bool {
    let mode = inode.i_mode();
    if !matches!(inode.file_type(), FileType::Regular) { return false; }
    if mode & S_ISUID != 0 { return false; }
    if (mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP) { return false; }
    inode_permission(inode, MAY_READ | MAY_WRITE, cred).is_ok()
}

/// Linux `may_linkat` + `vfs_link` source-side pre-backend gate. Destination
/// create permission and mount-identity ordering live in the syscall layer
/// because Linux runs `filename_create()` before `old_path.mnt != new_path.mnt`.
/// # C: O(ngroups)
pub fn may_link_source(src: &InodeRef, cred: &Cred) -> KResult<()> {
    if src.i_flags() & (crate::inode::S_APPEND | crate::inode::S_IMMUTABLE) != 0 {
        return Err(VfsError::Eperm);
    }
    if matches!(src.file_type(), FileType::Directory) { return Err(VfsError::Eperm); }
    if src.nlink() == 0 && src.i_state() & crate::inode::I_LINKABLE == 0 {
        return Err(VfsError::Enoent);
    }
    let max = src.i_sb().map(|sb| sb.s_max_links.load(Ordering::Relaxed)).unwrap_or(0);
    if max != 0 && src.nlink() >= max { return Err(VfsError::Emlink); }
    if PROTECTED_HARDLINKS
        && cred.uid != src.uid().unwrap_or(0)
        && !cred.cap_fowner
        && !safe_hardlink_source(src, cred)
    {
        return Err(VfsError::Eperm);
    }
    Ok(())
}

/// Combined destination+source hardlink gate for hosted VFS callers that are
/// not modeling syscall-level `filename_create()` / `EXDEV` ordering.
/// # C: O(ngroups)
pub fn may_link(parent: &InodeRef, src: &InodeRef, cred: &Cred) -> KResult<()> {
    may_create(parent, cred)?;
    may_link_source(src, cred)
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
    if let Some(t) = new_target {
        if alloc::sync::Arc::ptr_eq(old_victim, t) { return Ok(()); }
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

#[cfg(test)]
mod acl_tests {
    use super::*;

    // Build a POSIX ACL xattr: version 2 + `{tag,perm,id}` LE entries.
    fn acl(entries: &[(u16, u16, u32)]) -> alloc::vec::Vec<u8> {
        let mut b = alloc::vec![2u8, 0, 0, 0];
        for &(t, p, id) in entries {
            b.extend_from_slice(&t.to_le_bytes());
            b.extend_from_slice(&p.to_le_bytes());
            b.extend_from_slice(&id.to_le_bytes());
        }
        b
    }
    fn cred(uid: u32, gid: u32) -> Cred {
        Cred { uid, gid, cap_dac_override: false, cap_dac_read_search: false,
               cap_fowner: false, cap_chown: false, cap_fsetid: false,
               groups: crate::GroupList::empty() }
    }

    // owner=uid 100, group=500. USER 1000 rw; GROUP 2000 rw; MASK rw; OTHER r.
    fn fixture() -> alloc::vec::Vec<u8> {
        acl(&[(ACL_USER_OBJ, 7, u32::MAX), (ACL_USER, 6, 1000),
              (ACL_GROUP_OBJ, 4, u32::MAX), (ACL_GROUP, 6, 2000),
              (ACL_MASK, 6, u32::MAX), (ACL_OTHER, 4, u32::MAX)])
    }
    const R: u32 = MAY_READ; const W: u32 = MAY_WRITE; const X: u32 = MAY_EXEC;

    #[test] fn named_user_masked() {
        let a = fixture();
        assert_eq!(posix_acl_permission(&a, &cred(1000, 9), 100, 500, W), Some(true), "user 1000 rw grants write");
        assert_eq!(posix_acl_permission(&a, &cred(1000, 9), 100, 500, X), Some(false), "user 1000 rw denies exec");
    }
    #[test] fn named_group_and_deny_no_fallthrough() {
        let a = fixture();
        assert_eq!(posix_acl_permission(&a, &cred(2000, 2000), 100, 500, W), Some(true), "group 2000 rw grants write");
        // in a matched group but exec not granted -> DENY, never falls to OTHER's r.
        assert_eq!(posix_acl_permission(&a, &cred(2000, 2000), 100, 500, X), Some(false));
    }
    #[test] fn other_class() {
        let a = fixture();
        assert_eq!(posix_acl_permission(&a, &cred(3000, 3000), 100, 500, R), Some(true), "other reads");
        assert_eq!(posix_acl_permission(&a, &cred(3000, 3000), 100, 500, W), Some(false), "other cannot write");
    }
    #[test] fn owner_obj_unmasked() {
        let a = fixture();
        assert_eq!(posix_acl_permission(&a, &cred(100, 500), 100, 500, X), Some(true), "owner rwx incl exec (no mask)");
    }
    #[test] fn bad_or_absent() {
        assert_eq!(posix_acl_permission(&[], &cred(1, 1), 0, 0, R), None);
        assert_eq!(posix_acl_permission(&[1,0,0,0], &cred(1,1), 0,0, R), None, "wrong version");
    }
}
