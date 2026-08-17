// The ON-DISK ACL record, which is not the interchange form `set/getxattr`
// carries.
//
// Its header is one version word whose value is 1, not 2, and its entries are
// variable length: the four entries that name no id occupy four bytes, and only
// the named-user and named-group entries carry the extra id word. Every
// filesystem in this family writes byte-identical records — a volume written by
// one is read by the other — so the codec is here rather than copied into each,
// where the two copies could drift.
//
// A filesystem that stores this record converts at its own `i_op` xattr
// boundary: what lands on the medium is this form, and what a caller sets and
// gets is the interchange form.

extern crate alloc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use super::{ACL_GROUP, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER, ACL_UNDEFINED_ID, ACL_USER,
            ACL_USER_OBJ, AclEntry};

/// The stored header word (`EXT4_ACL_VERSION` / `F2FS_ACL_VERSION`), which is
/// not the interchange version.
pub const DISK_ACL_VERSION: u32 = 1;
/// `sizeof(..._acl_header)`.
const HDR_LEN: usize = 4;
/// `sizeof(..._acl_entry_short)` / `sizeof(..._acl_entry)`.
const SHORT_LEN: usize = 4;
const LONG_LEN:  usize = 8;

/// Whether a tag's record carries the id word. # C: O(1)
fn is_named(tag: u16) -> bool { tag == ACL_USER || tag == ACL_GROUP }

/// `..._acl_count` — how many entries a record of `size` bytes holds, on the
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

/// `..._acl_from_disk` — the stored record as entries.
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

/// `..._acl_to_disk` — entries as the stored record. An unrecognised tag is
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
    to_disk(&super::from_xattr(value)?)
}

/// The interchange blob for a stored record, for the read side. # C: O(N_entries)
pub fn xattr_from_disk(value: &[u8]) -> Result<Vec<u8>, Errno> {
    Ok(super::to_xattr(&from_disk(value)?))
}

/// The xattr-layer error a codec failure reports at the boundary it happened on:
/// a version this format did not write is `EOPNOTSUPP` to the caller, a record
/// that runs off its own region is the medium disagreeing with itself, and
/// anything else is a malformed value. # C: O(1)
pub fn xattr_error(e: Errno) -> crate::xattr::XattrError {
    match e {
        Errno::Eopnotsupp => crate::xattr::XattrError::NotSup,
        Errno::Euclean => crate::xattr::XattrError::Fs(crate::VfsError::Euclean),
        _ => crate::xattr::XattrError::Fs(crate::VfsError::Einval),
    }
}
