//! Final NT file-object deletion for `FILE_DELETE_ON_CLOSE`.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

/// Deferred deletion attached to one NT file object, not one handle.
pub struct NtDeleteOnClose {
    parent: Arc<vfs::Dentry>,
    dentry: Arc<vfs::Dentry>,
    victim: vfs::InodeRef,
    name: String,
    armed: AtomicBool,
}

impl NtDeleteOnClose {
    /// Prepare a final-close deletion for a regular file or empty directory.
    /// # C: O(1)
    pub fn new(file: &vfs::File, armed: bool) -> Option<Arc<Self>> {
        if !matches!(file.inode().file_type(), vfs::FileType::Regular | vfs::FileType::Directory) { return None; }
        Some(Arc::new(Self {
            parent: file.dentry().parent()?.clone(), dentry: file.dentry().clone(),
            victim: file.inode().clone(), name: String::from(file.dentry().name()), armed: AtomicBool::new(armed),
        }))
    }

    /// Change whether final object close removes the name. # C: O(1)
    pub fn set_armed(&self, armed: bool) { self.armed.store(armed, Ordering::Release); }

    /// Read the pending-delete state shared by duplicate handles. # C: O(1)
    pub fn is_armed(&self) -> bool { self.armed.load(Ordering::Acquire) }
}

impl Drop for NtDeleteOnClose {
    fn drop(&mut self) {
        if !self.is_armed() { return; }
        let Some(parent) = self.parent.inode() else { return; };
        let _guard = parent.inode_lock();
        let result = if self.victim.file_type() == vfs::FileType::Directory {
            parent.rmdir_with_victim(&self.name, &self.victim)
        } else { parent.unlink_child_with_victim(&self.name, &self.victim) };
        if result.is_ok() { vfs::dcache::d_unlink(&self.dentry); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
