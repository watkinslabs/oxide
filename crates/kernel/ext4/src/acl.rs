//! Ext4 default-ACL inheritance at the new-inode boundary.

use alloc::string::String;
use alloc::vec::Vec;

use vfs::posix_acl::{self, AclType, NewKind};
use vfs::{Inode, KResult, VfsError};

use crate::mount::{Mount, MountError};

/// The mode and stored ACL records a new inode receives from its parent.
pub(crate) struct Inherited {
    pub(crate) mode: u16,
    access: Option<Vec<u8>>,
    default: Option<Vec<u8>>,
}

/// Fold `parent`'s default ACL and `umask` into a new object's mode and ACLs.
/// A malformed parent ACL aborts the create rather than changing the requested
/// permissions by silently falling back to the umask. # C: O(N_entries)
pub(crate) fn inherit(parent: &Inode, mode: u16, umask: u16, kind: NewKind) -> KResult<Inherited> {
    let parent_default = match kind {
        NewKind::Symlink => None,
        _ => parent.get_inode_acl(AclType::Default)?,
    };
    let made = posix_acl::acl_create(parent_default.as_deref(), mode, umask, kind)
        .map_err(|e| VfsError::from_posix_errno(e as i32))?;
    let access = made.access.as_deref().map(posix_acl::disk::to_disk).transpose()
        .map_err(|e| VfsError::from_posix_errno(e as i32))?;
    let default = made.default.as_deref().map(posix_acl::disk::to_disk).transpose()
        .map_err(|e| VfsError::from_posix_errno(e as i32))?;
    Ok(Inherited { mode: made.mode, access, default })
}

impl Inherited {
    /// Store the new directory template before its access ACL in the caller's
    /// open metadata transaction. # C: O(N_entries)
    pub(crate) fn store(&self, mount: &Mount, ino: u32) -> Result<(), MountError> {
        let mut entries = Vec::new();
        if let Some(value) = &self.default {
            entries.push((String::from(posix_acl::XATTR_NAME_ACL_DEFAULT), value.clone()));
        }
        if let Some(value) = &self.access {
            entries.push((String::from(posix_acl::XATTR_NAME_ACL_ACCESS), value.clone()));
        }
        if entries.is_empty() { return Ok(()); }
        mount.store_xattrs(ino, &entries)
    }
}
