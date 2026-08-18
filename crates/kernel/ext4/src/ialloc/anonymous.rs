//! Anonymous inode creation and its crash-durable orphan-list enrollment.

use crate::inode::{Inode, S_IFREG};
use crate::mount::{Mount, MountError};

impl Mount {
    /// Create an anonymous regular file with the anonymous object's default
    /// owner ids. # C: O(1) inode allocation + metadata transaction
    pub fn create_anonymous(&self, parent_ino: u32, mode_perm: u16) -> Result<u32, MountError> {
        self.create_anonymous_as(parent_ino, mode_perm, 0, 0)
    }

    /// Create an anonymous regular file with explicit owner ids. # C: O(1)
    pub fn create_anonymous_as(&self, parent_ino: u32, mode_perm: u16, uid: u32, gid: u32)
        -> Result<u32, MountError>
    {
        self.create_anonymous_inode(parent_ino, mode_perm, uid, gid).map(|(ino, _)| ino)
    }

    /// Return a freshly allocated anonymous inode without an inherited ACL.
    /// # C: O(1) inode allocation + metadata transaction
    pub fn create_anonymous_inode(&self, parent_ino: u32, mode_perm: u16, uid: u32, gid: u32)
        -> Result<(u32, Inode), MountError>
    {
        self.create_anonymous_inode_inner(parent_ino, mode_perm, uid, gid, None)
    }

    /// Return a freshly allocated anonymous inode with its access ACL stored
    /// before it is enrolled in the orphan list. # C: same as `create_anonymous_inode`
    pub(crate) fn create_anonymous_inode_with_acl(
        &self,
        parent_ino: u32,
        mode_perm: u16,
        uid: u32,
        gid: u32,
        acl: &crate::acl::Inherited,
    ) -> Result<(u32, Inode), MountError> {
        self.create_anonymous_inode_inner(parent_ino, mode_perm, uid, gid, Some(acl))
    }

    fn create_anonymous_inode_inner(
        &self,
        parent_ino: u32,
        mode_perm: u16,
        uid: u32,
        gid: u32,
        acl: Option<&crate::acl::Inherited>,
    ) -> Result<(u32, Inode), MountError> {
        self.create_op(|m| {
            let parent_group = (parent_ino - 1) / m.sb.inodes_per_group;
            let new_ino = m.alloc_inode(parent_group)?;
            let node = m.init_inode(parent_ino, new_ino, S_IFREG | (mode_perm & 0x0FFF), 0, uid, gid)?;
            if let Some(acl) = acl { acl.store(m, new_ino)?; }
            m.orphan_add(new_ino)?;
            Ok((new_ino, node))
        })
    }
}
