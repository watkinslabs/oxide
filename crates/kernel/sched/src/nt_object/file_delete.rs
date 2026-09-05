//! Final NT file-object deletion for `FILE_DELETE_ON_CLOSE`.

extern crate alloc;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

/// Deferred deletion attached to one NT file object, not one handle.
pub struct NtDeleteOnClose {
    victim: vfs::InodeRef,
    armed: AtomicBool,
}

impl NtDeleteOnClose {
    /// Prepare a final-close deletion for a regular file or empty directory.
    /// # C: O(1)
    pub fn new(file: &vfs::File, armed: bool) -> Option<Arc<Self>> {
        if !matches!(file.inode().file_type(), vfs::FileType::Regular | vfs::FileType::Directory) { return None; }
        file.dentry().parent()?;
        Some(Arc::new(Self { victim: file.inode().clone(), armed: AtomicBool::new(armed) }))
    }

    /// Change whether final object close removes the name. # C: O(1)
    pub fn set_armed(&self, armed: bool) { self.armed.store(armed, Ordering::Release); }

    /// Read the pending-delete state shared by duplicate handles. # C: O(1)
    pub fn is_armed(&self) -> bool { self.armed.load(Ordering::Acquire) }
}

impl Drop for NtDeleteOnClose {
    fn drop(&mut self) {
        if !self.is_armed() { return; }
        // Rename publishes a new dentry and removes the old alias. Repeat
        // after a failed recheck so a concurrent rename can hand us its new
        // current alias without ever unlinking a replacement inode.
        for _ in 0..2 {
            let Some(dentry) = vfs::d_find_hashed_alias(&self.victim) else { return; };
            let Some(parent_dentry) = dentry.parent().cloned() else { continue; };
            let Some(parent) = parent_dentry.inode() else { return; };
            let _guard = parent.inode_lock();
            let current = dentry.is_hashed()
                && dentry.inode().is_some_and(|i| Arc::ptr_eq(&i, &self.victim))
                && parent_dentry.cached_child(dentry.name()).is_some_and(|c| Arc::ptr_eq(&c, &dentry));
            if !current { continue; }
            let result = if self.victim.file_type() == vfs::FileType::Directory {
                parent.rmdir_with_victim(dentry.name(), &self.victim)
            } else { parent.unlink_child_with_victim(dentry.name(), &self.victim) };
            if result.is_ok() { vfs::dcache::d_unlink(&dentry); }
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DeleteFs;
    impl vfs::FileSystemType for DeleteFs {
        fn name(&self) -> &str { "delete-test" }
        fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<alloc::sync::Arc<vfs::SuperBlock>> {
            Err(vfs::VfsError::Eperm)
        }
    }

    struct DeleteOps;
    impl vfs::InodeOps for DeleteOps {
        fn unlink(&self, _inode: &vfs::Inode, _name: &str) -> vfs::KResult<()> { Ok(()) }
    }

    fn test_sb() -> alloc::sync::Arc<vfs::SuperBlock> {
        vfs::SuperBlock::new(
            alloc::sync::Arc::new(DeleteFs),
            alloc::sync::Arc::new(vfs::SimpleSuperOps { magic: 1, block_size: 4096, options: alloc::string::String::new() }),
            1, 1, 4096, alloc::string::String::from("delete-test"), alloc::sync::Arc::new(()),
        )
    }

    fn test_root(sb: &alloc::sync::Arc<vfs::SuperBlock>) -> alloc::sync::Arc<vfs::Dentry> {
        let inode = vfs::InodeBuilder::new(
            1, vfs::mk_mode(vfs::FileType::Directory, 0o755),
            alloc::sync::Arc::new(DeleteOps), vfs::default_file_ops(),
        ).build();
        vfs::d_make_root(inode, sb)
    }

    #[test]
    fn pending_delete_state_is_shared_and_cancelable() {
        let parent_inode = vfs::make_static_file_inode(b"parent");
        let inode = vfs::make_static_file_inode(b"data");
        let parent = vfs::Dentry::new_root(parent_inode);
        let dentry = vfs::Dentry::new(Some(parent), alloc::string::String::from("data"), inode.clone());
        let file = vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDONLY);
        let state = NtDeleteOnClose::new(file.as_ref(), false).unwrap();
        assert!(!state.is_armed());
        state.set_armed(true); assert!(state.is_armed());
        state.set_armed(false); assert!(!state.is_armed());
    }

    #[test]
    fn final_close_deletes_current_alias_after_rename() {
        let sb = test_sb();
        let root = test_root(&sb);
        let inode = vfs::make_static_file_inode(b"data");
        inode.bind_superblock(&sb);
        let old = vfs::d_add(&root, "old", inode.clone());
        let file = vfs::File::new(inode, old, vfs::OpenFlags::O_RDONLY);
        let state = NtDeleteOnClose::new(file.as_ref(), true).unwrap();
        vfs::d_move(file.dentry(), &root, "current");
        drop(state);
        assert!(vfs::d_lookup(&root, "old").and_then(|d| d.inode()).is_none());
        assert!(vfs::d_lookup(&root, "current").and_then(|d| d.inode()).is_none(), "final close removes renamed alias");
    }

    #[test]
    fn final_close_does_not_remove_replacement_inode() {
        let sb = test_sb();
        let root = test_root(&sb);
        let victim = vfs::make_static_file_inode(b"victim");
        victim.bind_superblock(&sb);
        let old = vfs::d_add(&root, "old", victim.clone());
        let file = vfs::File::new(victim, old, vfs::OpenFlags::O_RDONLY);
        let state = NtDeleteOnClose::new(file.as_ref(), true).unwrap();
        vfs::d_move(file.dentry(), &root, "current");
        let current = vfs::d_lookup(&root, "current").unwrap();
        vfs::dcache::d_unlink(&current);
        let replacement = vfs::make_static_file_inode(b"replacement");
        replacement.bind_superblock(&sb);
        vfs::d_add(&root, "current", replacement.clone());
        drop(state);
        assert!(vfs::d_lookup(&root, "current").is_some(), "replacement inode remains named");
        assert!(vfs::d_find_hashed_alias(&replacement).is_some());
    }
}
