//! POSIX ACLs: this filesystem's own on-disk record, and what a newly created
//! object inherits from its parent directory.
//!
//! The record is NOT the interchange form `set/getxattr` carries, and its codec
//! is shared with every other filesystem that writes the same bytes
//! (`vfs::posix_acl::disk`). What this module owns is the pair of attribute
//! NAMES the volume stores them under and the create-time inheritance; the
//! conversion happens at the `i_op` xattr boundary, where the attribute is read
//! and written.
//!
//! Inheritance is the other half. A directory may carry a DEFAULT ACL, which is
//! the template for everything created inside it: it decides the new object's
//! permission bits instead of the umask, it becomes the new object's access ACL
//! when the mode bits cannot express it, and a new DIRECTORY takes a verbatim
//! copy so the template propagates down the tree.

use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::posix_acl::{self, NewKind};

use crate::uapi::{XATTR_INDEX_POSIX_ACL_ACCESS, XATTR_INDEX_POSIX_ACL_DEFAULT};

pub use vfs::posix_acl::disk::{DISK_ACL_VERSION, disk_from_xattr, from_disk, to_disk,
                               xattr_from_disk};

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
