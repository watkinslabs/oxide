//! Mounting an NTFS volume: the VFS-facing filesystem, its inodes and their
//! operations.
//!
//! Everything below this file is pure and already tested against images in
//! memory. This is the adapter.
//!
//! Module manifest:
//! - `node`: what an inode of this filesystem is, and the mode it presents.
//! - `ops`:  the inode and file operations.
//! - `sb`:   `statfs`, the option tail, and the dirty flag at unmount.

use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};

use syscall::errno::Errno;

use sectors::BlockSource;
use vfs::{InodeRef, KResult, VfsError};

use crate::opts::Options;
use crate::volume::Volume;

pub mod node;
pub mod ops;
pub mod sb;

/// The one name this filesystem is registered under.
pub const NTFS_NAME: &str = "ntfs3";

/// A mounted NTFS filesystem.
pub struct NtfsFs {
    /// One lock: a write mutates the two bitmaps every read consults.
    pub(crate) volume: sync::Spinlock<Volume<BlockSource>, sync::TaskList>,
    source: String,
    me: Weak<NtfsFs>,
}

impl NtfsFs {
    /// Mount the volume on `dev`, read-only. # C: O(MFT + bitmap bytes)
    pub fn open(dev: Arc<dyn block::BlockDevice>, source: &str) -> KResult<Arc<Self>> {
        let mut opts = Options::defaults();
        opts.settle();
        Self::open_with(dev, source, false, opts)
    }

    /// Mount under an option set.
    ///
    /// A volume its last owner left dirty mounts READ-ONLY, which is not what
    /// FAT and exFAT do and is deliberate: this filesystem has a journal, and
    /// writing to a volume whose journal has not been replayed loses whatever
    /// the journal was about to redo. `force` overrides it, exactly as the
    /// reference does.
    /// # C: O(MFT + bitmap bytes)
    pub fn open_with(dev: Arc<dyn block::BlockDevice>, source: &str, write: bool, opts: Options)
        -> KResult<Arc<Self>> {
        let mut volume = Volume::mount_with(BlockSource::new(dev).writable(write), opts)
            .map_err(errno_to_vfs)?;
        if volume.was_dirty() && !opts.force {
            klog::warn::warn_on(true,
                "ntfs3: volume is marked dirty; mounting read-only, run chkdsk or pass force");
            volume.set_read_only();
        }
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

    /// Clear the dirty flag — unmount. # C: O(record bytes)
    pub fn mark_clean(&self) -> KResult<()> {
        let mut v = self.volume.lock();
        if !v.writable() { return Ok(()); }
        v.set_dirty(false).map_err(errno_to_vfs)
    }

    /// The root inode. # C: O(record bytes)
    pub fn root_inode(self: &Arc<Self>) -> KResult<InodeRef> {
        let info = self.volume.lock().stat(crate::uapi::MFT_REC_ROOT).map_err(errno_to_vfs)?;
        Ok(node::node_inode(Arc::clone(self), info))
    }

    /// The volume's name. # C: O(label length)
    pub fn label(&self) -> String { self.volume.lock().label() }

    /// Rename the volume. # C: O(record bytes)
    pub fn set_label(&self, name: &str) -> KResult<()> {
        self.volume.lock().set_label(name).map_err(errno_to_vfs)
    }

    /// This mount's option set. # C: O(1)
    pub fn options(&self) -> Options { *self.volume.lock().options() }

    /// The device this filesystem was mounted from. # C: O(1)
    pub fn source(&self) -> &str { &self.source }
}

/// The current wall clock as a stored timestamp. # C: O(1)
pub fn now() -> i64 {
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
        Errno::Eacces => VfsError::Eacces,
        Errno::Eopnotsupp => VfsError::Eopnotsupp,
        _ => VfsError::Eio,
    }
}

impl vfs::fs::FileSystem for NtfsFs {
    fn name(&self) -> &str { NTFS_NAME }
    fn magic(&self) -> u64 { crate::uapi::NTFS_SUPER_MAGIC }
    fn fs_flags(&self) -> vfs::fs::FsFlags { vfs::fs::FsFlags::FS_REQUIRES_DEV }
    fn block_size(&self) -> u32 { self.volume.lock().geometry().cluster_size }
    fn show_options(&self) -> String { crate::opts::show(self.volume.lock().options()) }
    fn super_ops(&self) -> Option<Arc<dyn vfs::superblock::SuperOps>> {
        self.me.upgrade()
            .map(|fs| Arc::new(sb::NtfsSuperOps { fs }) as Arc<dyn vfs::superblock::SuperOps>)
    }
}

/// Read the whole of `path` from a mounted volume. # C: O(file bytes)
pub fn read_path(fs: &NtfsFs, path: &str) -> KResult<alloc::vec::Vec<u8>> {
    let v = fs.volume.lock();
    let hit = v.lookup(path).map_err(errno_to_vfs)?;
    if hit.is_dir() { return Err(VfsError::Eisdir); }
    v.read_whole(hit.reference.number).map_err(errno_to_vfs)
}
