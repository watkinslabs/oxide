#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use sync::{Spinlock, TaskList as LockClass};
use vfs::{Dentry, FileType, InodeBuilder, InodeRef, default_file_ops, default_inode_ops, mk_mode};

use super::registry::NEXT_FSCTX_INO;

pub struct FsContextInode {
    pub fstype: String,
    pub fc: Spinlock<Option<vfs::fs::FsContext>, LockClass>,
}

impl FsContextInode {
    pub fn new(fstype: String, ty: Arc<dyn vfs::FileSystemType>) -> InodeRef {
        Self::build(fstype, Some(vfs::fs::FsContext::for_mount(ty, 0)))
    }

    pub fn new_reconfigure(fstype: String, fc: vfs::fs::FsContext) -> InodeRef {
        Self::build(fstype, Some(fc))
    }

    fn build(fstype: String, fc: Option<vfs::fs::FsContext>) -> InodeRef {
        let ino = NEXT_FSCTX_INO.fetch_add(1, Ordering::Relaxed);
        InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o600), default_inode_ops(), default_file_ops())
            .private(Arc::new(Self { fstype, fc: Spinlock::new(fc) }))
            .build()
    }
}

pub struct MountObjectInode {
    pub fstype: String,
    pub realized: Option<(Arc<vfs::SuperBlock>, Arc<Dentry>)>,
    pub mnt_attrs: AtomicU64,
    /// Kernel-internal `mnt_flags` (`MNT_LOCK_*` / `MNT_LOCKED`) decided at
    /// `fsmount(2)` and applied when `move_mount(2)` grafts this object. Linux
    /// takes both decisions inside `do_fsmount` — `mount_too_revealing`'s
    /// "preserve the locked attributes" and `create_new_namespace`'s
    /// `lock_mnt_tree` — because it materialises the `vfsmount` there; this tree
    /// defers mount creation to `move_mount`, so the WORD travels on the object
    /// while the DECISION stays at the Linux syscall.
    pub mnt_lock_flags: AtomicU32,
    pub clone_of: Option<(Arc<dyn vfs::fs::FileSystem>, InodeRef)>,
    pub detached_tree: Spinlock<Option<vfs::mount::DetachedMountTree>, LockClass>,
}

impl Drop for MountObjectInode {
    fn drop(&mut self) {
        if let Some(tree) = self.detached_tree.lock().take() {
            vfs::mount::release_clone_tree(&tree);
        }
    }
}

impl MountObjectInode {
    pub fn new_realized(sb: Arc<vfs::SuperBlock>, root: Arc<Dentry>, fstype: String, mnt_attrs: u64,
        mnt_lock_flags: u32) -> InodeRef {
        Self::build(Self { fstype, realized: Some((sb, root)), mnt_attrs: AtomicU64::new(mnt_attrs), mnt_lock_flags: AtomicU32::new(mnt_lock_flags), clone_of: None, detached_tree: Spinlock::new(None) })
    }

    pub fn new_clone(fs: Arc<dyn vfs::fs::FileSystem>, root: InodeRef) -> InodeRef {
        Self::build(Self { fstype: String::new(), realized: None, mnt_attrs: AtomicU64::new(0), mnt_lock_flags: AtomicU32::new(0), clone_of: Some((fs, root)), detached_tree: Spinlock::new(None) })
    }

    pub fn new_clone_tree(tree: vfs::mount::DetachedMountTree) -> InodeRef {
        Self::build(Self { fstype: String::new(), realized: None, mnt_attrs: AtomicU64::new(0), mnt_lock_flags: AtomicU32::new(0), clone_of: None, detached_tree: Spinlock::new(Some(tree)) })
    }

    fn build(data: Self) -> InodeRef {
        let ino = NEXT_FSCTX_INO.fetch_add(1, Ordering::Relaxed);
        InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o600), default_inode_ops(), default_file_ops())
            .private(Arc::new(data))
            .build()
    }
}
