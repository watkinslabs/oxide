//! Inode-facing names for the single VFS sleeping-rwsem owner.

pub type InodeRwsem = crate::rwsem::VfsRwsem<sync::Inode>;
pub type InodeRwsemReadGuard<'a> = crate::rwsem::VfsRwsemReadGuard<'a, sync::Inode>;
pub type InodeRwsemWriteGuard<'a> = crate::rwsem::VfsRwsemWriteGuard<'a, sync::Inode>;

/// Install scheduler wait hooks for every VFS sleeping rwsem. # C: O(1)
pub fn set_inode_rwsem_wait_hooks(
    park: fn(usize, bool), schedule: fn(), wake: fn(usize, bool),
) {
    crate::rwsem::set_vfs_rwsem_wait_hooks(park, schedule, wake);
}

/// Clear process-global VFS rwsem wait hooks for hosted tests. # C: O(1)
pub fn clear_inode_rwsem_wait_hooks() {
    crate::rwsem::clear_vfs_rwsem_wait_hooks();
}
