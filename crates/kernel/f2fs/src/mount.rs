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
    /// Kept so freed space can be announced to the device. The volume reads
    /// and writes through a sector source that deliberately exposes only
    /// those two operations; discard is a property of the DEVICE, not of the
    /// medium abstraction, and belongs here.
    dev: Arc<dyn block::BlockDevice>,
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
        let keep = Arc::clone(&dev);
        let src = BlockSource::new(dev)
            .with_sector_size(BLKSIZE as u32)
            .writable(write);
        let volume = Volume::mount_with(src, opts, write).map_err(errno_to_vfs)?;
        if volume.access() == Access::ReadOnly {
            klog::warn::warn_on(true, "f2fs: volume is marked read-only; mounting read-only");
        }
        let source = source.to_string();
        Ok(Arc::new_cyclic(|me| Self {
            dev: keep,
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

    /// The volume, with its clock set to this instant.
    ///
    /// Every mutation takes the lock through this rather than `volume.lock()`.
    /// Two things are measured against that clock and both fail silently
    /// without it: a segment's age, which decides which segment the cleaner
    /// picks, and a soft quota limit's grace period, which is an absolute
    /// expiry. A volume nobody tells the time to measures every grace against
    /// zero, so none ever comes due, and every segment reads the same age, so
    /// cost-benefit selection degenerates to lowest-numbered.
    /// # C: O(1)
    pub(crate) fn volume_now(&self)
        -> sync::Guard<'_, Volume<BlockSource>, sync::TaskList>
    {
        let mut v = self.volume.lock();
        v.set_clock(crate::mount::write::now().0);
        v
    }

    /// Push everything to the medium and leave the volume consistent.
    ///
    /// A checkpoint is what turns this mount's out-of-place writes into a
    /// filesystem state; without one the medium still describes the state the
    /// mount started from.
    /// # C: O(dirty blocks)
    pub fn mark_clean(&self) -> KResult<()> { self.checkpoint() }

    /// Write a checkpoint, then announce what it freed.
    ///
    /// The order is the contract. Until the checkpoint lands, every released
    /// block is still referenced by the checkpoint on the medium — announcing
    /// one first destroys the state a crash would recover to.
    /// # C: O(dirty blocks + freed runs)
    pub fn checkpoint(&self) -> KResult<()> {
        let runs = {
            let mut v = self.volume.lock();
            v.commit().map_err(errno_to_vfs)?;
            v.take_discards()
        };
        self.announce_free(&runs);
        Ok(())
    }

    /// Tell the device it may forget these runs.
    ///
    /// Best effort by nature: a discard that fails costs nothing but the
    /// space staying marked used on the device, so a failure is not allowed
    /// to fail the checkpoint that already succeeded.
    /// # C: O(runs)
    fn announce_free(&self, runs: &[(u32, u32)]) {
        if runs.is_empty() || !self.dev.supports_discard() { return; }
        let dev_block = u64::from(self.dev.block_size().max(1));
        for &(start, len) in runs {
            let byte = u64::from(start) * BLKSIZE as u64;
            let bytes = u64::from(len) * BLKSIZE as u64;
            if byte % dev_block != 0 || bytes % dev_block != 0 { continue; }
            let first = byte / dev_block;
            let Ok(blocks) = u32::try_from(bytes / dev_block) else { continue };
            let mut req = block::BlockRequest::new_discard(first, blocks);
            let _ = self.dev.submit_sync(&mut req);
        }
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

#[cfg(test)]
#[path = "tests/adapter.rs"]
mod tests;
