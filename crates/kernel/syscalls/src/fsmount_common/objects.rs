#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Spinlock, TaskList as LockClass};
use vfs::{Dentry, FileType, InodeBuilder, InodeRef, default_file_ops, default_inode_ops, mk_mode};

use super::registry::{NEXT_FSCTX_INO, ensure_filesystems_registered, fstype_converted};

pub struct FsContextInode {
    pub fstype: String,
    pub source: Spinlock<String, LockClass>,
    pub options: Spinlock<Vec<(String, String)>, LockClass>,
    pub fc: Spinlock<Option<vfs::fs::FsContext>, LockClass>,
}

impl FsContextInode {
    pub fn new(fstype: String) -> InodeRef {
        let fc = if fstype_converted(&fstype) {
            ensure_filesystems_registered();
            vfs::fs::get_fs_type(&fstype).map(|ty| vfs::fs::FsContext::for_mount(ty, 0))
        } else {
            None
        };
        Self::build(fstype, fc)
    }

    pub fn new_reconfigure(fstype: String, fc: vfs::fs::FsContext) -> InodeRef {
        Self::build(fstype, Some(fc))
    }

    fn build(fstype: String, fc: Option<vfs::fs::FsContext>) -> InodeRef {
        let ino = NEXT_FSCTX_INO.fetch_add(1, Ordering::Relaxed);
        InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o600), default_inode_ops(), default_file_ops())
            .private(Arc::new(Self { fstype, source: Spinlock::new(String::new()), options: Spinlock::new(Vec::new()), fc: Spinlock::new(fc) }))
            .build()
    }
}

pub struct MountObjectInode {
    pub fstype: String,
    pub source: String,
    pub realized: Option<(Arc<vfs::SuperBlock>, Arc<Dentry>)>,
    pub mnt_attrs: AtomicU64,
    pub clone_of: Option<(Arc<dyn vfs::fs::FileSystem>, InodeRef)>,
    pub detached_tree: Spinlock<Option<Vec<vfs::mount::CloneNode>>, LockClass>,
}

impl Drop for MountObjectInode {
    fn drop(&mut self) {
        if let Some(tree) = self.detached_tree.lock().take() {
            vfs::mount::release_clone_tree(&tree);
        }
    }
}

impl MountObjectInode {
    pub fn new(fstype: String, source: String, mnt_attrs: u64) -> InodeRef {
        Self::build(Self { fstype, source, realized: None, mnt_attrs: AtomicU64::new(mnt_attrs), clone_of: None, detached_tree: Spinlock::new(None) })
    }

    pub fn new_realized(sb: Arc<vfs::SuperBlock>, root: Arc<Dentry>, fstype: String, source: String, mnt_attrs: u64) -> InodeRef {
        Self::build(Self { fstype, source, realized: Some((sb, root)), mnt_attrs: AtomicU64::new(mnt_attrs), clone_of: None, detached_tree: Spinlock::new(None) })
    }

    pub fn new_clone(fs: Arc<dyn vfs::fs::FileSystem>, root: InodeRef) -> InodeRef {
        Self::build(Self { fstype: String::new(), source: String::new(), realized: None, mnt_attrs: AtomicU64::new(0), clone_of: Some((fs, root)), detached_tree: Spinlock::new(None) })
    }

    pub fn new_clone_tree(tree: Vec<vfs::mount::CloneNode>) -> InodeRef {
        Self::build(Self { fstype: String::new(), source: String::new(), realized: None, mnt_attrs: AtomicU64::new(0), clone_of: None, detached_tree: Spinlock::new(Some(tree)) })
    }

    fn build(data: Self) -> InodeRef {
        let ino = NEXT_FSCTX_INO.fetch_add(1, Ordering::Relaxed);
        InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o600), default_inode_ops(), default_file_ops())
            .private(Arc::new(data))
            .build()
    }
}
