//! Mounting an F2FS volume: the VFS-facing filesystem, its inodes and their
//! operations.
//!
//! Everything below this file is pure and already tested against images in
//! memory — including the write path, which is proved by writing an image and
//! mounting its bytes again. This is the adapter, and the only layer that
//! reaches the block layer.
//!
//! Module manifest:
//! - `node`: what an inode of this filesystem is, built from a stored one.
//! - `ops`:  the inode and file operations.
//! - `sb`:   `statfs` and the option tail.
//! - `write`: the mutating operations, and the clock they share.

use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};

use syscall::errno::Errno;

use sectors::BlockSource;
use vfs::{InodeRef, KResult, VfsError};

use crate::features::Access;
use crate::opts::Options;
use crate::uapi::BLKSIZE;
use crate::volume::Volume;

pub mod node;
pub mod ops;
pub mod sb;
pub mod write;

/// The one name this filesystem is registered under.
pub const F2FS_NAME: &str = "f2fs";

/// A mounted F2FS filesystem.
pub struct F2fs {
    /// One lock: the volume caches the checkpoint and both journals, which
    /// every read consults.
    pub(crate) volume: sync::Spinlock<Volume<BlockSource>, sync::TaskList>,
    source: String,
    /// Held so the superblock operations can reach the filesystem they belong
    /// to, which the `&self` those operations are asked for cannot.
    me: Weak<F2fs>,
}

impl F2fs {
    /// Mount the volume on `dev`, read-only. # C: O(checkpoint bytes)
    pub fn open(dev: Arc<dyn block::BlockDevice>, source: &str) -> KResult<Arc<Self>> {
        Self::open_with(dev, source, false, Options::defaults())
    }

    /// Mount under an option set.
    ///
    /// A volume whose own features permit only reads mounts READ-ONLY even
    /// when the caller asked to write, and reports that through
    /// [`Self::is_writable`] so the superblock can be marked accordingly.
    /// Reporting writable when the volume is not fails every write at the
    /// first one instead of at the mount.
    /// # C: O(checkpoint bytes)
    pub fn open_with(dev: Arc<dyn block::BlockDevice>, source: &str, write: bool, opts: Options)
        -> KResult<Arc<Self>> {
        // The volume's own unit is the block, and the source is aimed at it
        // directly: a block address IS the sector number this reads through,
        // so no second unit exists to disagree.
        let src = BlockSource::new(dev)
            .with_sector_size(BLKSIZE as u32)
            .writable(write);
        let volume = Volume::mount_with(src, opts, write).map_err(errno_to_vfs)?;
        if volume.access() == Access::ReadOnly {
            klog::warn::warn_on(true, "f2fs: volume is marked read-only; mounting read-only");
        }
        let source = source.to_string();
        Ok(Arc::new_cyclic(|me| Self {
            volume: sync::Spinlock::new(volume),
            source,
            me: me.clone(),
        }))
    }

    /// Whether this mount ended up writable.
    ///
    /// A mount that asked to write a volume whose own features forbid it, or
    /// a medium that refuses writes, reports false here so the superblock can
    /// be marked read-only — failing every write at the first one instead of
    /// at the mount is the outcome this avoids.
    /// # C: O(1)
    pub fn is_writable(&self) -> bool { self.volume.lock().writable() }

    /// Push everything to the medium and leave the volume consistent.
    ///
    /// A checkpoint is what turns this mount's out-of-place writes into a
    /// filesystem state; without one the medium still describes the state the
    /// mount started from.
    /// # C: O(dirty blocks)
    pub fn mark_clean(&self) -> KResult<()> {
        self.volume.lock().commit().map_err(errno_to_vfs)
    }

    /// The root inode. # C: O(1 block)
    pub fn root_inode(self: &Arc<Self>) -> KResult<InodeRef> {
        let ino = self.volume.lock().root_ino();
        node::node_inode(Arc::clone(self), ino)
    }

    /// This mount's option set. # C: O(1)
    pub fn options(&self) -> Options { *self.volume.lock().options() }

    /// The device this filesystem was mounted from. # C: O(1)
    pub fn source(&self) -> &str { &self.source }
}

/// # C: O(1)
pub fn errno_to_vfs(err: Errno) -> VfsError {
    match err {
        Errno::Einval => VfsError::Einval,
        Errno::Enoent => VfsError::Enoent,
        Errno::Eisdir => VfsError::Eisdir,
        Errno::Enotdir => VfsError::Enotdir,
        Errno::Enotempty => VfsError::Enotempty,
        Errno::Eexist => VfsError::Eexist,
        Errno::Enospc => VfsError::Enospc,
        Errno::Erofs => VfsError::Erofs,
        Errno::Enametoolong => VfsError::Enametoolong,
        Errno::Efbig => VfsError::Efbig,
        Errno::Enomem => VfsError::Enomem,
        Errno::Eopnotsupp => VfsError::Eopnotsupp,
        Errno::Enodata => VfsError::Enodata,
        _ => VfsError::Eio,
    }
}

impl vfs::fs::FileSystem for F2fs {
    fn name(&self) -> &str { F2FS_NAME }
    fn magic(&self) -> u64 { crate::uapi::F2FS_SUPER_MAGIC }
    fn fs_flags(&self) -> vfs::fs::FsFlags { vfs::fs::FsFlags::FS_REQUIRES_DEV }
    fn block_size(&self) -> u32 { BLKSIZE as u32 }
    fn show_options(&self) -> String { crate::opts::show(self.volume.lock().options()) }
    fn super_ops(&self) -> Option<Arc<dyn vfs::superblock::SuperOps>> {
        self.me
            .upgrade()
            .map(|fs| Arc::new(sb::F2fsSuperOps { fs }) as Arc<dyn vfs::superblock::SuperOps>)
    }
}
