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
use vfs::posix_acl::{self, AclEntry};

/// `S_ISGID` in `Umode` terms.
const S_ISGID: u16 = 0o2000;

/// Is `name` one of the two whole-name POSIX-ACL handlers? # C: O(1)
pub fn is_acl_name(name: &str) -> bool { name == NAME_ACL_ACCESS || name == NAME_ACL_DEFAULT }

/// `posix_acl_fix_xattr_common` + the `posix_acl_from_xattr` decode. An empty
/// entry list decodes to "no ACL" (Linux `NULL`), which REMOVES the attribute.
/// # C: O(N_entries)
fn decode(value: &[u8]) -> Result<Vec<AclEntry>, i64> {
    posix_acl::from_xattr(value).map_err(err)
}

/// `posix_acl_valid`. # C: O(N_entries)
fn validate(entries: &[AclEntry]) -> Result<(), i64> {
    posix_acl::validate(entries).map_err(err)
}

/// `posix_acl_update_mode` — rewrite `i_mode` from the ACL and drop the S_ISGID
/// bit when the caller is neither in the file's group nor CAP_FSETID.
/// # C: O(N_entries) + backend setattr
fn update_mode(inode: &InodeRef, entries: &[AclEntry], c: &XattrCred) -> Result<bool, i64> {
    let mut mode = inode.i_mode() as u16;
    let keep = posix_acl::equiv_mode(entries, &mut mode).map_err(err)?;
    if !c.cred.in_group(inode.gid().unwrap_or(0)) && !c.cred.cap_fsetid { mode &= !S_ISGID; }
    let ia = vfs::Iattr { valid: vfs::ATTR_MODE, mode: mode & 0o7777, ..Default::default() };
    inode.setattr(&vfs::IDENTITY, &ia).map_err(|e| -(e as i64))?;
    Ok(keep)
}

/// `do_set_acl` → `vfs_set_acl` → `set_posix_acl`. The generic set flags are
/// deliberately unused: Linux drops them before this path. # C: O(N_entries)
pub fn set_acl(inode: &InodeRef, name: &str, value: Vec<u8>, c: &XattrCred) -> Result<(), i64> {
    if inode.i_sb().is_some_and(|sb| !sb.is_posixacl()) { return Err(err(Errno::Eopnotsupp)); }
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
    if inode.i_sb().is_some_and(|sb| !sb.is_posixacl()) { return Err(err(Errno::Eopnotsupp)); }
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
