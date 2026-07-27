// POSIX-ACL half of `setxattr`/`getxattr`/`removexattr`. Linux routes the two
// `system.posix_acl_*` names AROUND the generic handler stack: `do_setxattr` →
// `do_set_acl` → `posix_acl_from_xattr` (blob validation) → `vfs_set_acl` →
// `may_write_xattr` → `set_posix_acl` (default-on-non-dir, owner check,
// `posix_acl_valid`) → `i_op->set_acl` (which runs `posix_acl_update_mode`, so
// an access ACL rewrites `i_mode` and a mode-equivalent ACL is dropped).
// XATTR_CREATE/XATTR_REPLACE are NOT consulted on this path.

extern crate alloc;
use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::{FileType, InodeRef};

use super::policy::{err, may_write_xattr, XattrCred, NAME_ACL_ACCESS, NAME_ACL_DEFAULT};

/// POSIX ACL entry tags (`uapi/linux/posix_acl.h`).
const ACL_USER_OBJ:  u16 = 0x01;
const ACL_USER:      u16 = 0x02;
const ACL_GROUP_OBJ: u16 = 0x04;
const ACL_GROUP:     u16 = 0x08;
const ACL_MASK:      u16 = 0x10;
const ACL_OTHER:     u16 = 0x20;
/// `POSIX_ACL_XATTR_VERSION`.
const ACL_XATTR_VERSION: u32 = 2;
/// `sizeof(struct posix_acl_xattr_header)` / `..._entry`.
const ACL_HDR_LEN:   usize = 4;
const ACL_ENTRY_LEN: usize = 8;
/// `ACL_READ|ACL_WRITE|ACL_EXECUTE` — every legal `e_perm` bit.
const ACL_PERM_MASK: u16 = 0o7;
/// `S_IRWXU|S_IRWXG|S_IRWXO` and `S_ISGID` in `Umode` terms.
const S_IRWXUGO: u16 = 0o777;
const S_IRWXO:   u16 = 0o7;
const S_IRWXG:   u16 = 0o70;
const S_ISGID:   u16 = 0o2000;

/// One decoded `struct posix_acl_xattr_entry`.
#[derive(Clone, Copy)]
struct AclEntry { tag: u16, perm: u16, id: u32 }

/// Is `name` one of the two whole-name POSIX-ACL handlers? # C: O(1)
pub fn is_acl_name(name: &str) -> bool { name == NAME_ACL_ACCESS || name == NAME_ACL_DEFAULT }

/// `posix_acl_fix_xattr_common` + the `posix_acl_from_xattr` decode. An empty
/// entry list decodes to "no ACL" (Linux `NULL`), which REMOVES the attribute.
/// # C: O(N_entries)
fn decode(value: &[u8]) -> Result<Vec<AclEntry>, i64> {
    if value.len() < ACL_HDR_LEN { return Err(err(Errno::Einval)); }
    let ver = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
    if ver != ACL_XATTR_VERSION { return Err(err(Errno::Eopnotsupp)); }
    let body = &value[ACL_HDR_LEN..];
    if body.len() % ACL_ENTRY_LEN != 0 { return Err(err(Errno::Einval)); }
    let mut out = Vec::new();
    for e in body.chunks_exact(ACL_ENTRY_LEN) {
        out.push(AclEntry {
            tag:  u16::from_le_bytes([e[0], e[1]]),
            perm: u16::from_le_bytes([e[2], e[3]]),
            id:   u32::from_le_bytes([e[4], e[5], e[6], e[7]]),
        });
    }
    Ok(out)
}

/// `posix_acl_valid` — the entry sequence must be USER_OBJ, USER*, GROUP_OBJ,
/// GROUP*, MASK?, OTHER, a MASK is mandatory once any USER/GROUP entry exists,
/// and no `e_perm` bit outside rwx may be set. # C: O(N_entries)
fn validate(entries: &[AclEntry]) -> Result<(), i64> {
    let einval = Err(err(Errno::Einval));
    // `state` tracks which tag is legal next; 0 means "sequence complete".
    let mut state = ACL_USER_OBJ;
    let mut needs_mask = false;
    for e in entries {
        if e.perm & !ACL_PERM_MASK != 0 { return einval; }
        match e.tag {
            ACL_USER_OBJ  => { if state != ACL_USER_OBJ { return einval; } state = ACL_USER; }
            ACL_USER      => { if state != ACL_USER { return einval; } needs_mask = true; }
            ACL_GROUP_OBJ => { if state != ACL_USER { return einval; } state = ACL_GROUP; }
            ACL_GROUP     => { if state != ACL_GROUP { return einval; } needs_mask = true; }
            ACL_MASK      => { if state != ACL_GROUP { return einval; } state = ACL_OTHER; }
            ACL_OTHER     => {
                if state == ACL_OTHER || (state == ACL_GROUP && !needs_mask) { state = 0; }
                else { return einval; }
            }
            _ => return einval,
        }
    }
    if state == 0 { Ok(()) } else { einval }
}

/// `posix_acl_equiv_mode` — fold the three base entries into permission bits.
/// Returns `true` when the ACL carries information the mode bits CANNOT express
/// (a named user/group or a mask), i.e. Linux's `not_equiv`. # C: O(N_entries)
fn equiv_mode(entries: &[AclEntry], mode: &mut u16) -> bool {
    let mut perm: u16 = 0;
    let mut not_equiv = false;
    for e in entries {
        match e.tag {
            ACL_USER_OBJ  => perm |= (e.perm & S_IRWXO) << 6,
            ACL_GROUP_OBJ => perm |= (e.perm & S_IRWXO) << 3,
            ACL_OTHER     => perm |= e.perm & S_IRWXO,
            ACL_MASK      => { perm = (perm & !S_IRWXG) | ((e.perm & S_IRWXO) << 3); not_equiv = true; }
            _             => not_equiv = true,
        }
    }
    *mode = (*mode & !S_IRWXUGO) | perm;
    not_equiv
}

/// `posix_acl_update_mode` — rewrite `i_mode` from the ACL and drop the S_ISGID
/// bit when the caller is neither in the file's group nor CAP_FSETID.
/// # C: O(N_entries) + backend setattr
fn update_mode(inode: &InodeRef, entries: &[AclEntry], c: &XattrCred) -> Result<bool, i64> {
    let mut mode = inode.i_mode() as u16;
    let keep = equiv_mode(entries, &mut mode);
    if !c.cred.in_group(inode.gid().unwrap_or(0)) && !c.cred.cap_fsetid { mode &= !S_ISGID; }
    let ia = vfs::Iattr { valid: vfs::ATTR_MODE, mode: mode & 0o7777, ..Default::default() };
    inode.setattr(&vfs::IDENTITY, &ia).map_err(|e| -(e as i64))?;
    Ok(keep)
}

/// `do_set_acl` → `vfs_set_acl` → `set_posix_acl`. The generic set flags are
/// deliberately unused: Linux drops them before this path. # C: O(N_entries)
pub fn set_acl(inode: &InodeRef, name: &str, value: Vec<u8>, c: &XattrCred) -> Result<(), i64> {
    let entries = decode(&value)?;
    may_write_xattr(inode)?;
    let is_dir = inode.file_type() == FileType::Directory;
    if name == NAME_ACL_DEFAULT && !is_dir {
        return if entries.is_empty() { Ok(()) } else { Err(err(Errno::Eacces)) };
    }
    if !c.owns(inode) { return Err(err(Errno::Eperm)); }
    if entries.is_empty() { return drop_stored(inode, name); }
    validate(&entries)?;
    // An access ACL is also the file's mode; a mode-equivalent ACL is not stored.
    if name == NAME_ACL_ACCESS && !update_mode(inode, &entries, c)? {
        return drop_stored(inode, name);
    }
    inode.setxattr(name, value, false, false).map_err(super::ops::xattr_errno)?;
    super::ops::notify_xattr(inode);
    Ok(())
}

/// `vfs_remove_acl` — same inode restrictions, then unconditional removal.
/// A missing ACL is not an error (Linux `set_cached_acl(NULL)`). # C: O(1)
pub fn remove_acl(inode: &InodeRef, name: &str, c: &XattrCred) -> Result<(), i64> {
    may_write_xattr(inode)?;
    if name == NAME_ACL_DEFAULT && inode.file_type() != FileType::Directory { return Ok(()); }
    if !c.owns(inode) { return Err(err(Errno::Eperm)); }
    drop_stored(inode, name)
}

/// Remove the stored blob, tolerating "already absent". # C: O(log N)
fn drop_stored(inode: &InodeRef, name: &str) -> Result<(), i64> {
    match inode.removexattr(name) {
        Ok(()) => { super::ops::notify_xattr(inode); Ok(()) }
        Err(vfs::XattrError::NotFound) => Ok(()),
        Err(e) => Err(super::ops::xattr_errno(e)),
    }
}
