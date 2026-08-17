//! POSIX ACLs: this filesystem's own on-disk record, and what a newly created
//! object inherits from its parent directory.
//!
//! The record is NOT the interchange form `set/getxattr` carries. Its header is
//! one version word whose value is 1, not 2, and its entries are variable
//! length: the four entries that name no id occupy four bytes, and only the
//! named-user and named-group entries carry the extra id word. Storing the
//! interchange blob verbatim would write a version this format rejects and give
//! every entry a length the reader does not expect, so both directions convert
//! here, at the boundary where the attribute is read and written.
//!
//! Inheritance is the other half. A directory may carry a DEFAULT ACL, which is
//! the template for everything created inside it: it decides the new object's
//! permission bits instead of the umask, it becomes the new object's access ACL
//! when the mode bits cannot express it, and a new DIRECTORY takes a verbatim
//! copy so the template propagates down the tree.

use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::posix_acl::{self, AclEntry, NewKind, ACL_GROUP, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER,
                     ACL_UNDEFINED_ID, ACL_USER, ACL_USER_OBJ};

use crate::uapi::{XATTR_INDEX_POSIX_ACL_ACCESS, XATTR_INDEX_POSIX_ACL_DEFAULT};

/// `F2FS_ACL_VERSION` — the on-disk header word, which is not the interchange
/// version.
pub const DISK_ACL_VERSION: u32 = 1;
/// `sizeof(struct f2fs_acl_header)`.
const HDR_LEN: usize = 4;
/// `sizeof(struct f2fs_acl_entry_short)` / `struct f2fs_acl_entry`.
const SHORT_LEN: usize = 4;
const LONG_LEN:  usize = 8;

/// Whether a tag's record carries the id word. # C: O(1)
fn is_named(tag: u16) -> bool { tag == ACL_USER || tag == ACL_GROUP }

/// The two attribute names whose VALUE is a stored ACL record rather than the
/// bytes the caller handed over. Taken from the index table so the name and the
/// index it is stored under cannot drift apart. # C: O(1)
pub fn name_access()  -> &'static str { name_of(XATTR_INDEX_POSIX_ACL_ACCESS) }
/// The name of the template a directory hands to what is created inside it.
/// # C: O(1)
pub fn name_default() -> &'static str { name_of(XATTR_INDEX_POSIX_ACL_DEFAULT) }

fn name_of(index: u8) -> &'static str {
    match crate::xattr::prefix_of(index) { Some(n) => n, None => "" }
}

/// Is this attribute one of the two stored as an ACL record? # C: O(1)
pub fn is_acl_name(name: &str) -> bool { name == name_access() || name == name_default() }

/// `f2fs_acl_count` — how many entries a record of `size` bytes holds, on the
/// assumption that the first four are short ones. It is a length CHECK as much
/// as a count: a size that is not a whole number of records has none.
/// # C: O(1)
fn disk_count(size: usize) -> Option<usize> {
    let size = size.checked_sub(HDR_LEN)?;
    match size.checked_sub(4 * SHORT_LEN) {
        None => if size % SHORT_LEN == 0 { Some(size / SHORT_LEN) } else { None },
        Some(rest) => if rest % LONG_LEN == 0 { Some(rest / LONG_LEN + 4) } else { None },
    }
}

/// `f2fs_acl_from_disk` — the stored record as entries.
///
/// Errno order, which a caller reports as-is: a truncated header, a version this
/// format did not write, or a size that is not a whole number of records is
/// `EINVAL` — a malformed ARGUMENT; a record that runs off the end of the region
/// is `EUCLEAN` — the medium disagrees with itself; an unrecognised tag, or a
/// walk that does not land exactly on the end, is `EINVAL` again. An empty
/// record is no ACL at all, not an empty one.
/// # C: O(N_entries)
pub fn from_disk(value: &[u8]) -> Result<Vec<AclEntry>, Errno> {
    if value.len() < HDR_LEN { return Err(Errno::Einval); }
    let ver = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
    if ver != DISK_ACL_VERSION { return Err(Errno::Einval); }
    let count = disk_count(value.len()).ok_or(Errno::Einval)?;
    let mut out = Vec::with_capacity(count);
    let mut at = HDR_LEN;
    for _ in 0..count {
        let head = value.get(at..at + SHORT_LEN).ok_or(Errno::Euclean)?;
        let tag  = u16::from_le_bytes([head[0], head[1]]);
        let perm = u16::from_le_bytes([head[2], head[3]]);
        let (id, len) = if is_named(tag) {
            let idw = value.get(at + SHORT_LEN..at + LONG_LEN).ok_or(Errno::Euclean)?;
            (u32::from_le_bytes([idw[0], idw[1], idw[2], idw[3]]), LONG_LEN)
        } else if matches!(tag, ACL_USER_OBJ | ACL_GROUP_OBJ | ACL_MASK | ACL_OTHER) {
            (ACL_UNDEFINED_ID, SHORT_LEN)
        } else {
            return Err(Errno::Einval);
        };
        out.push(AclEntry { tag, perm, id });
        at += len;
    }
    if at != value.len() { return Err(Errno::Einval); }
    Ok(out)
}

/// `f2fs_acl_to_disk` — entries as the stored record. An unrecognised tag is
/// `EINVAL`; nothing is written for it. # C: O(N_entries)
pub fn to_disk(entries: &[AclEntry]) -> Result<Vec<u8>, Errno> {
    let mut out = Vec::with_capacity(HDR_LEN + entries.len() * LONG_LEN);
    out.extend_from_slice(&DISK_ACL_VERSION.to_le_bytes());
    for e in entries {
        if !is_named(e.tag) && !matches!(e.tag, ACL_USER_OBJ | ACL_GROUP_OBJ | ACL_MASK | ACL_OTHER) {
            return Err(Errno::Einval);
        }
        out.extend_from_slice(&e.tag.to_le_bytes());
        out.extend_from_slice(&e.perm.to_le_bytes());
        if is_named(e.tag) { out.extend_from_slice(&e.id.to_le_bytes()); }
    }
    Ok(out)
}

/// The stored record for an interchange blob, for the write side of the xattr
/// boundary. # C: O(N_entries)
pub fn disk_from_xattr(value: &[u8]) -> Result<Vec<u8>, Errno> {
    to_disk(&posix_acl::from_xattr(value)?)
}

/// The interchange blob for a stored record, for the read side. # C: O(N_entries)
pub fn xattr_from_disk(value: &[u8]) -> Result<Vec<u8>, Errno> {
    Ok(posix_acl::to_xattr(&from_disk(value)?))
}

/// What a new object under a directory is created with: the mode the parent's
/// default ACL and the umask agree on, and the two records to store on it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Inherited {
    /// Permission bits for the new inode.
    pub mode: u16,
    /// `system.posix_acl_access`, already in the stored form.
    pub access: Option<Vec<u8>>,
    /// `system.posix_acl_default`, already in the stored form.
    pub default: Option<Vec<u8>>,
}

impl Inherited {
    /// Nothing inherited: the umask alone decides. # C: O(1)
    fn plain(mode: u16) -> Self { Inherited { mode, access: None, default: None } }
}

/// `f2fs_init_acl` — decide the new object's mode and the ACLs to store on it
/// from `parent_default`, the parent directory's stored default-ACL record.
///
/// `enabled` is the mount's `acl` option (`IS_POSIXACL`): without it the umask
/// alone decides and nothing is inherited, which is the same answer the generic
/// layer reaches when a filesystem does not support ACLs at all. A parent whose
/// record cannot be decoded fails the CREATE rather than silently falling back
/// to the umask: the alternative is a file whose permissions nobody asked for.
/// # C: O(N_entries)
pub fn inherit(parent_default: Option<&[u8]>, mode: u16, umask: u16, kind: NewKind,
               enabled: bool) -> Result<Inherited, Errno>
{
    if !enabled || kind == NewKind::Symlink {
        return Ok(Inherited::plain(if kind == NewKind::Symlink { mode } else { mode & !umask }));
    }
    let parent = match parent_default {
        Some(bytes) => Some(from_disk(bytes)?),
        None => None,
    };
    let new = posix_acl::acl_create(parent.as_deref(), mode, umask, kind)?;
    Ok(Inherited {
        mode: new.mode,
        access:  new.access.as_deref().map(to_disk).transpose()?,
        default: new.default.as_deref().map(to_disk).transpose()?,
    })
}

#[cfg(test)]
#[path = "tests/acl.rs"]
mod tests;
