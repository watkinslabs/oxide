//! Mounting an exFAT volume: the VFS-facing filesystem, its inodes and their
//! operations.
//!
//! Everything below this file is pure and already tested against images in
//! memory. This is the adapter, and the decisions it owns are the ones the
//! layers below cannot make: what an inode NUMBER is on a filesystem that
//! stores none, and which VFS type and mode each entry presents as. Both live
//! in `ident` and `node`, ungated and tested, because this module reaches the
//! block layer and would otherwise be untestable.
//!
//! Module manifest:
//! - `node`: what an inode of this filesystem is, and the mode it presents.
//! - `ops`:  the inode and file operations, which are one vector here.
//! - `sb`:   `statfs`, the option tail, and flushing at unmount.

use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};

use syscall::errno::Errno;

use sectors::BlockSource;
use vfs::{InodeRef, KResult, VfsError};

use crate::opts::Options;
use crate::time::Stamp;
use crate::volume::{DirHandle, Volume};

pub mod node;
pub mod ops;
pub mod sb;

/// The one name this filesystem is registered under.
pub const EXFAT_NAME: &str = "exfat";

/// A mounted exFAT filesystem.
pub struct ExfatFs {
    /// One lock: a write mutates the in-memory bitmap and table every read
    /// consults.
    pub(crate) volume: sync::Spinlock<Volume<BlockSource>, sync::TaskList>,
    source: String,
    /// Held so the superblock operations can reach the filesystem they belong
    /// to, which the `&self` those operations are asked for cannot.
    me: Weak<ExfatFs>,
}

impl ExfatFs {
    /// Mount the volume on `dev`, read-only. # C: O(table + bitmap bytes)
    pub fn open(dev: Arc<dyn block::BlockDevice>, source: &str) -> KResult<Arc<Self>> {
        let mut opts = Options::defaults();
        opts.settle();
        Self::open_with(dev, source, false, opts)
    }

    /// Mount under an option set.
    ///
    /// A volume its last owner left dirty mounts read-WRITE and warns that a
    /// check is due, which is what the reference does. Refusing would leave a
    /// user unable to save anything to a card that was pulled once; the
    /// warning is what tells them to run a check.
    /// # C: O(table + bitmap bytes)
    pub fn open_with(dev: Arc<dyn block::BlockDevice>, source: &str, write: bool, opts: Options)
        -> KResult<Arc<Self>> {
        let mut volume = Volume::mount_with(BlockSource::new(dev).writable(write), opts)
            .map_err(errno_to_vfs)?;
        if volume.was_dirty() {
            klog::warn::warn_on(true,
                "exfat: volume was not properly unmounted; some data may be corrupt, run fsck");
        }
        // Marking is a no-op on a volume already dirty: the flag it carries is
        // its last owner's, and this mount has not repaired anything.
        if volume.writable() { volume.set_dirty(true).map_err(errno_to_vfs)?; }
        let source = source.to_string();
        Ok(Arc::new_cyclic(|me| Self {
            volume: sync::Spinlock::new(volume),
            source,
            me: me.clone(),
        }))
    }

    /// Whether this mount ended up writable. # C: O(1)
    pub fn is_writable(&self) -> bool { self.volume.lock().writable() }

    /// Whether the volume was found dirty. # C: O(1)
    pub fn was_dirty(&self) -> bool { self.volume.lock().was_dirty() }

    /// Clear the dirty flag — unmount.
    ///
    /// The in-use percentage goes out first: a volume marked clean while that
    /// byte is stale tells the next reader a number nobody has checked.
    /// # C: O(1 sector)
    pub fn mark_clean(&self) -> KResult<()> {
        let mut v = self.volume.lock();
        if !v.writable() { return Ok(()); }
        v.flush_percent_in_use().map_err(errno_to_vfs)?;
        v.set_dirty(false).map_err(errno_to_vfs)
    }

    /// The root inode. # C: O(1)
    pub fn root_inode(self: &Arc<Self>) -> InodeRef {
        node::node_inode(Arc::clone(self), None, DirHandle::Root)
    }

    /// This mount's option set. # C: O(1)
    pub fn options(&self) -> Options { *self.volume.lock().options() }

    /// The device this filesystem was mounted from. # C: O(1)
    pub fn source(&self) -> &str { &self.source }
}

/// The current wall clock as a stored timestamp.
///
/// One reading per operation, taken once and used for every field it stamps,
/// so a file's creation and modification times cannot disagree by the width of
/// the work between them.
/// # C: O(1)
pub fn now() -> Stamp {
    let ns = vfs::inode_times::realtime_now_ns();
    crate::time::from_unix(vfs::timespec::Timespec64::from_clock_ns(ns))
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
        _ => VfsError::Eio,
    }
}

impl vfs::fs::FileSystem for ExfatFs {
    fn name(&self) -> &str { EXFAT_NAME }
    fn magic(&self) -> u64 { crate::uapi::EXFAT_SUPER_MAGIC }
    fn fs_flags(&self) -> vfs::fs::FsFlags { vfs::fs::FsFlags::FS_REQUIRES_DEV }
    fn block_size(&self) -> u32 { self.volume.lock().geometry().sector_size }
    fn show_options(&self) -> String { crate::opts::show(self.volume.lock().options()) }
    fn super_ops(&self) -> Option<Arc<dyn vfs::superblock::SuperOps>> {
        self.me.upgrade()
            .map(|fs| Arc::new(sb::ExfatSuperOps { fs }) as Arc<dyn vfs::superblock::SuperOps>)
    }
}

/// Read the whole of `path` from a mounted volume. Exists for a boot-time
/// caller that wants one file without a mount point. # C: O(file bytes)
pub fn read_path(fs: &ExfatFs, path: &str) -> KResult<alloc::vec::Vec<u8>> {
    let v = fs.volume.lock();
    let hit = v.lookup(path).map_err(errno_to_vfs)?;
    if hit.is_dir() { return Err(VfsError::Eisdir); }
    v.read_whole(&hit).map_err(errno_to_vfs)
}
