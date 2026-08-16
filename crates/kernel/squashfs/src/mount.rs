//! Mounting a squashfs image: the VFS-facing filesystem, its inodes and their
//! operations.
//!
//! Everything below this file is pure and already tested against images in
//! memory. This is the adapter, and it owns one decision the layers below
//! cannot make: which VFS type each stored type word means. That lives in
//! `node`, ungated and tested, because this module reaches the block layer and
//! would otherwise be untestable.
//!
//! There is no write path and no slot left at its default by accident. The
//! image is immutable, the superblock says so, and the operations this file
//! does not implement answer the way a filesystem without them does.
//!
//! Module manifest:
//! - `node`: what an inode of this filesystem is, and the type it presents.
//! - `ops`:  the inode and file operations, which are one vector here.
//! - `sb`:   `statfs` and the option tail.

use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};

use syscall::errno::Errno;

use sectors::BlockSource;
use vfs::{InodeRef, KResult, VfsError};

use crate::opts::Options;
use crate::volume::{MountError, Volume};

pub mod node;
pub mod ops;
pub mod sb;

/// The one name this filesystem is registered under.
pub const SQUASHFS_NAME: &str = "squashfs";

/// A squashfs image is byte-addressed from its very first byte, so the volume's
/// sector is one byte and the adapter below turns that into whatever unit the
/// device wants.
const VOLUME_SECTOR: u32 = 1;

/// A mounted squashfs filesystem.
pub struct SquashFs {
    /// One lock: the metadata cache is shared, and a decompression under it is
    /// what every reader is waiting for.
    pub(crate) volume: sync::Spinlock<Volume<BlockSource>, sync::TaskList>,
    source: String,
    /// Held so the superblock operations can reach the filesystem they belong
    /// to, which the `&self` those operations are asked for cannot.
    me: Weak<SquashFs>,
}

impl SquashFs {
    /// Mount the image on `dev`. # C: O(index table bytes)
    pub fn open(dev: Arc<dyn block::BlockDevice>, source: &str) -> KResult<Arc<Self>> {
        Self::open_with(dev, source, false, Options::defaults())
    }

    /// Mount under an option set.
    ///
    /// `write` is accepted and ignored on purpose: this format has no write
    /// path at all, so a caller asking for one gets a read-only mount and the
    /// superblock says so. Failing the mount would leave a caller who passed
    /// no flags at all unable to mount an image that is perfectly readable.
    /// # C: O(index table bytes)
    pub fn open_with(dev: Arc<dyn block::BlockDevice>, source: &str, _write: bool, opts: Options)
        -> KResult<Arc<Self>> {
        let src = BlockSource::new(dev).with_sector_size(VOLUME_SECTOR);
        let volume = Volume::mount_with(src, opts).map_err(mount_to_vfs)?;
        let source = source.to_string();
        Ok(Arc::new_cyclic(|me| Self {
            volume: sync::Spinlock::new(volume),
            source,
            me: me.clone(),
        }))
    }

    /// Always false: the format records no way to change an image in place.
    /// # C: O(1)
    pub fn is_writable(&self) -> bool { false }

    /// The root inode. # C: O(root inode bytes)
    pub fn root_inode(self: &Arc<Self>) -> KResult<InodeRef> {
        let reference = self.volume.lock().root_reference();
        node::inode_for(self, reference)
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
        Errno::Enametoolong => VfsError::Enametoolong,
        Errno::Erofs => VfsError::Erofs,
        Errno::Enomem => VfsError::Enomem,
        _ => VfsError::Eio,
    }
}

/// Why a mount failed, in the VFS's terms.
///
/// A refusal is `EINVAL` and a medium failure is `EIO`, which is the
/// distinction a caller acts on: the first says this image is not for this
/// reader, the second says the read did not happen.
/// # C: O(1)
pub fn mount_to_vfs(err: MountError) -> VfsError {
    match err {
        MountError::Super(_) | MountError::Table(_) | MountError::Truncated => VfsError::Einval,
        MountError::Io(e) => errno_to_vfs(e),
    }
}

impl vfs::fs::FileSystem for SquashFs {
    fn name(&self) -> &str { SQUASHFS_NAME }
    fn magic(&self) -> u64 { crate::uapi::SQUASHFS_SUPER_MAGIC }
    fn fs_flags(&self) -> vfs::fs::FsFlags { vfs::fs::FsFlags::FS_REQUIRES_DEV }
    fn block_size(&self) -> u32 { self.volume.lock().superblock().block_size }
    fn show_options(&self) -> String { crate::opts::show(*self.volume.lock().options()) }
    fn super_ops(&self) -> Option<Arc<dyn vfs::superblock::SuperOps>> {
        self.me.upgrade()
            .map(|fs| Arc::new(sb::SquashSuperOps { fs }) as Arc<dyn vfs::superblock::SuperOps>)
    }
}

/// Read the whole of `path` from a mounted image. Exists for a boot-time
/// caller that wants one file without a mount point. # C: O(file bytes)
pub fn read_path(fs: &SquashFs, path: &str) -> KResult<alloc::vec::Vec<u8>> {
    let v = fs.volume.lock();
    let mut node = v.read_inode(v.root_reference()).map_err(errno_to_vfs)?;
    for part in path.split('/') {
        if part.is_empty() || part == "." { continue; }
        let hit = v.lookup(&node, part).map_err(errno_to_vfs)?;
        node = v.read_inode(hit.reference).map_err(errno_to_vfs)?;
    }
    if matches!(node.kind, crate::volume::Kind::Dir { .. }) { return Err(VfsError::Eisdir); }
    v.read_whole(&node).map_err(errno_to_vfs)
}
