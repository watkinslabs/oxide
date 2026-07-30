#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use sync::{Spinlock, TaskList as LockClass};
use vfs::{Dentry, FileType, InodeBuilder, InodeRef, default_file_ops, default_inode_ops, mk_mode};

use super::registry::NEXT_FSCTX_INO;

pub struct FsContextInode {
    pub fstype: String,
    pub fc: Spinlock<Option<vfs::fs::FsContext>, LockClass>,
}

impl FsContextInode {
    /// Allocate a mount-purpose filesystem context inode. # C: O(1)
    pub fn new(fstype: String, ty: Arc<dyn vfs::FileSystemType>) -> InodeRef {
        Self::build(fstype, Some(vfs::fs::FsContext::for_mount(ty, 0)))
    }

    /// Allocate a reconfiguration filesystem context inode. # C: O(1)
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
    /// The single lock-protected property set of a realized mount that Oxide
    /// defers materializing until `move_mount`. Linux has a real detached
    /// `struct mount` here; keeping attrs, locked bits and idmap together gives
    /// the deferred representation the same prepare/commit serialization.
    pub mount_state: Spinlock<MountObjectState, LockClass>,
    pub clone_of: Option<(Arc<dyn vfs::fs::FileSystem>, InodeRef)>,
    pub detached_tree: Spinlock<Option<vfs::mount::DetachedMountTree>, LockClass>,
}

#[derive(Clone)]
pub struct MountObjectState {
    /// Raw userspace `MOUNT_ATTR_*` option bits (IDMAP lives in `idmap`).
    pub attrs: u64,
    /// Kernel-internal `MNT_LOCK_* | MNT_LOCKED` word.
    pub lock_flags: u32,
    /// Pending immutable idmap for a realized fsmount.
    pub idmap: Option<Arc<vfs::idmap::Idmap>>,
    /// Pending propagation transition, if mount_setattr requested one.
    pub propagation: Option<vfs::mount::Propagation>,
}

impl Drop for MountObjectInode {
    fn drop(&mut self) {
        if let Some(tree) = self.detached_tree.lock().take() {
            vfs::mount::release_clone_tree(&tree);
        }
    }
}

impl MountObjectInode {
    /// Build a deferred fsmount object around a realized superblock. # C: O(1)
    pub fn new_realized(sb: Arc<vfs::SuperBlock>, root: Arc<Dentry>, fstype: String, mnt_attrs: u64,
        mnt_lock_flags: u32) -> InodeRef {
        Self::build(Self {
            fstype, realized: Some((sb, root)),
            mount_state: Spinlock::new(MountObjectState {
                attrs: mnt_attrs, lock_flags: mnt_lock_flags, idmap: None, propagation: None,
            }),
            clone_of: None, detached_tree: Spinlock::new(None),
        })
    }

    /// Build a detached legacy filesystem clone object. # C: O(1)
    pub fn new_clone(fs: Arc<dyn vfs::fs::FileSystem>, root: InodeRef) -> InodeRef {
        Self::build(Self {
            fstype: String::new(), realized: None,
            mount_state: Spinlock::new(MountObjectState {
                attrs: 0, lock_flags: 0, idmap: None, propagation: None,
            }),
            clone_of: Some((fs, root)), detached_tree: Spinlock::new(None),
        })
    }

    /// Build an open_tree clone object owning one detached mount tree. # C: O(1)
    pub fn new_clone_tree(tree: vfs::mount::DetachedMountTree) -> InodeRef {
        Self::build(Self {
            fstype: String::new(), realized: None,
            mount_state: Spinlock::new(MountObjectState {
                attrs: 0, lock_flags: 0, idmap: None, propagation: None,
            }),
            clone_of: None, detached_tree: Spinlock::new(Some(tree)),
        })
    }

    fn build(data: Self) -> InodeRef {
        let ino = NEXT_FSCTX_INO.fetch_add(1, Ordering::Relaxed);
        InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o600), default_inode_ops(), default_file_ops())
            .private(Arc::new(data))
            .build()
    }
}
