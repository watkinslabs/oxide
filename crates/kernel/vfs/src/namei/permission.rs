use crate::inode::InodeRef;
use crate::types::{FileType, KResult, VfsError};

use super::{Cred, MAY_EXEC, MAY_READ, MAY_WRITE};

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
///
/// "Nobody gets write access to an immutable file" (Linux `inode_permission`):
/// the S_IMMUTABLE reject stands AHEAD of the DAC dispatch, so it is EPERM for
/// every caller including root — a capability grants permission, not the right
/// to ignore the flag. This is what makes `chattr +i` refuse `open(O_WRONLY)`,
/// `truncate`, and every other write-intent path from one place instead of
/// each of them re-testing the flag.
/// # C: O(ngroups)
pub fn inode_permission(inode: &InodeRef, mask: u32, cred: &Cred) -> KResult<()> {
    if mask & MAY_WRITE != 0 && inode.i_flags() & crate::inode::S_IMMUTABLE != 0 {
        return Err(VfsError::Eperm);
    }
    inode.permission(mask, cred)?;
    super::device_permission(inode.file_type(), inode.rdev(), mask)
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
