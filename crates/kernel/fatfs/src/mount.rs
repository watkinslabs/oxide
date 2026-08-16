//! Mounting a FAT volume: the VFS-facing filesystem, its inodes and their
//! operations.
//!
//! Everything below this file is pure and already tested against images in
//! memory. This is the adapter, and the decisions it owns are the ones the
//! layers below cannot make: what an inode NUMBER is on a filesystem that has
//! none, and which VFS type and mode each entry presents as.
//!
//! Both of those live in `ident` and `node`, ungated and tested, because this
//! module reaches the block layer and would otherwise be untestable.
//!
//! Module manifest:
//! - `node`:   what an inode of this filesystem is, and the mode it presents.
//! - `ops`:    the inode and file operations, which are all one vector here.
//! - `sb`:     `statfs`, the option tail, and flushing at unmount.

use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};

use syscall::errno::Errno;

use vfs::{InodeRef, KResult, VfsError};

use crate::ident::DirLocation;
use crate::opts::Options;
use crate::time::{from_unix, FatTime};
use crate::volume::Volume;

pub mod node;
pub mod ops;
pub mod sb;

// The adapter over a block device is shared with every other on-disk
// filesystem; see `sectors::device`.
pub use sectors::BlockSource;
pub use node::FatNode;

/// Linux's magic for a FAT superblock. Both types carry it: they are one
/// on-disk format seen through two sets of naming rules.
pub const MSDOS_SUPER_MAGIC: u64 = 0x4d44;

/// The two names this one implementation is registered under.
pub const VFAT_NAME: &str = "vfat";
pub const MSDOS_NAME: &str = "msdos";

/// A mounted FAT filesystem.
pub struct FatFs {
    /// One lock: a write mutates the in-memory table every read consults.
    volume: sync::Spinlock<Volume<BlockSource>, sync::TaskList>,
    source: String,
    /// Which of the two type names this mount was made under. The medium is
    /// the same either way; the naming rules are not.
    type_name: &'static str,
    /// Held so the superblock operations can reach the filesystem they belong
    /// to, which the `&self` those operations are asked for cannot.
    me: Weak<FatFs>,
}

impl FatFs {
    /// Mount the volume on `dev`, read-only, under the long-name rules.
    /// # C: O(table bytes)
    pub fn open(dev: Arc<dyn block::BlockDevice>, source: &str) -> KResult<Arc<Self>> {
        Self::open_with_access(dev, source, false)
    }

    /// Mount under the long-name rules, asking for write access.
    /// # C: O(table bytes)
    pub fn open_with_access(dev: Arc<dyn block::BlockDevice>, source: &str, write: bool)
        -> KResult<Arc<Self>> {
        let mut opts = Options::vfat();
        opts.settle();
        Self::open_typed(dev, source, write, VFAT_NAME, opts)
    }

    /// Mount under a named type and option set.
    ///
    /// A volume its last owner left dirty mounts read-WRITE and warns that a
    /// check is due, which is what the reference does. Refusing would leave a
    /// user unable to save anything to a stick that was pulled once; the
    /// warning is what tells them to run a check.
    /// # C: O(table bytes)
    pub fn open_typed(dev: Arc<dyn block::BlockDevice>, source: &str, write: bool,
                      type_name: &'static str, opts: Options) -> KResult<Arc<Self>> {
        let volume = Volume::mount_with(BlockSource::new(dev).writable(write), opts)
            .map_err(errno_to_vfs)?;
        if volume.was_dirty() {
            klog::warn::warn_on(true,
                "vfat: volume was not properly unmounted; some data may be corrupt, run fsck");
        }
        // Marking is a no-op on a volume already dirty: the flag it carries is
        // its last owner's, and this mount has not repaired anything.
        if volume.writable() { volume.set_dirty(true).map_err(errno_to_vfs)?; }
        let source = source.to_string();
        Ok(Arc::new_cyclic(|me| Self {
            volume: sync::Spinlock::new(volume),
            source,
            type_name,
            me: me.clone(),
        }))
    }

    /// Whether this mount ended up writable. # C: O(1)
    pub fn is_writable(&self) -> bool { self.volume.lock().writable() }

    /// Whether the volume was found dirty. # C: O(1)
    pub fn was_dirty(&self) -> bool { self.volume.lock().was_dirty() }

    /// Clear the dirty flag — unmount.
    ///
    /// The information sector goes out first: it carries the free count the
    /// next mount starts from, and a volume marked clean while that count is
    /// stale tells the next reader a number nobody has checked.
    /// # C: O(1 sector)
    pub fn mark_clean(&self) -> KResult<()> {
        let mut v = self.volume.lock();
        if !v.writable() { return Ok(()); }
        v.flush_fsinfo().map_err(errno_to_vfs)?;
        v.set_dirty(false).map_err(errno_to_vfs)
    }

    /// The root inode. # C: O(1)
    pub fn root_inode(self: &Arc<Self>) -> InodeRef {
        let location = {
            let v = self.volume.lock();
            if v.geometry().has_fixed_root() { DirLocation::FixedRoot }
            else { DirLocation::Cluster(v.geometry().root_cluster) }
        };
        node::node_inode(Arc::clone(self), None, location, None, 0, 1)
    }

    /// This mount's option set. # C: O(1)
    pub fn options(&self) -> Options { *self.volume.lock().options() }
}

/// The current wall clock as the fields a record stores, under this mount's
/// own idea of local time.
///
/// One reading per operation, taken once and used for every field it stamps,
/// so a file's creation and modification times cannot disagree by the width of
/// the work between them.
/// # C: O(1)
pub fn now_for(opts: &Options) -> FatTime {
    let ns = vfs::inode_times::realtime_now_ns();
    from_unix(&opts.time, vfs::timespec::Timespec64::from_clock_ns(ns))
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

impl vfs::fs::FileSystem for FatFs {
    fn name(&self) -> &str { self.type_name }
    fn magic(&self) -> u64 { MSDOS_SUPER_MAGIC }
    fn fs_flags(&self) -> vfs::fs::FsFlags { vfs::fs::FsFlags::FS_REQUIRES_DEV }
    fn block_size(&self) -> u32 { self.volume.lock().geometry().sector_size }
    // The root inode is handed to the superblock by the mount constructor
    // rather than produced here: building it needs the `Arc` that owns this
    // filesystem, and this method only has a borrow.
    fn show_options(&self) -> String { crate::opts::show(self.volume.lock().options()) }
    fn super_ops(&self) -> Option<Arc<dyn vfs::superblock::SuperOps>> {
        self.me.upgrade().map(|fs| Arc::new(sb::FatSuperOps { fs }) as Arc<dyn vfs::superblock::SuperOps>)
    }
}

/// Read the whole of `path` from a mounted volume. Exists for the boot-time
/// caller that wants one file without a mount point. # C: O(file bytes)
pub fn read_path(fs: &FatFs, path: &str) -> KResult<alloc::vec::Vec<u8>> {
    let v = fs.volume.lock();
    let hit = v.lookup(path).map_err(errno_to_vfs)?;
    if hit.is_dir() { return Err(VfsError::Eisdir); }
    let mut out = alloc::vec![0u8; usize::try_from(hit.entry.size).map_err(|_| VfsError::Einval)?];
    let got = v.read_file(&hit.entry, 0, &mut out).map_err(errno_to_vfs)?;
    out.truncate(got);
    Ok(out)
}

/// The device this filesystem was mounted from. # C: O(1)
pub fn source_of(fs: &FatFs) -> &str { &fs.source }

#[cfg(test)]
#[path = "mount/tests.rs"]
mod tests;
