//! The inode and file operations of a mounted FAT volume.
//!
//! One vector serves both, because on this filesystem an inode and an open
//! file need exactly the same three things: the record the inode came from,
//! the directory that record sits in, and the volume's lock.
//!
//! There is deliberately no `link`. FAT has no link count and no way to name
//! one file twice — a second name would be a second record claiming the same
//! first cluster, which every checker reports as cross-linked — so the slot is
//! left at its default, which answers `EPERM`, exactly as a filesystem without
//! the operation does. `symlink`, `mknod` and `tmpfile` are absent for the
//! same reason.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{CreateCtx, DirContext, FileOps, FileType, Inode, InodeOps, InodeRef, KResult,
          VfsError};

use crate::ident::{self, DirLocation};
use crate::namei::dir_is_empty;
use crate::volume::{DirEntry, DirHandle};

use super::node::{node_inode, FatNode};
use super::{errno_to_vfs, now_for};

/// The operations, for every inode of this filesystem.
pub struct FatOps;

impl FatOps {
    /// The node behind an inode. # C: O(1)
    fn node(inode: &Inode) -> KResult<&FatNode> {
        inode.private::<FatNode>().ok_or(VfsError::Einval)
    }

    /// The node behind a DIRECTORY inode, and the handle to operate in it.
    /// # C: O(1)
    fn dir_of(inode: &Inode) -> KResult<(&FatNode, DirHandle)> {
        let node = Self::node(inode)?;
        let dir = node.as_dir().ok_or(VfsError::Enotdir)?;
        Ok((node, dir))
    }

    /// The directory contents an inode names, or `ENOTDIR`. # C: O(dir bytes)
    fn entries(node: &FatNode) -> KResult<Vec<DirEntry>> {
        let dir = node.as_dir().ok_or(VfsError::Enotdir)?;
        node.fs.volume.lock().read_dir(dir.cluster).map_err(errno_to_vfs)
    }

    /// Build the inode for an entry found in `parent`. # C: O(cluster bytes)
    fn child(node: &FatNode, dir: &DirHandle, hit: &DirEntry) -> InodeRef {
        let location = ident::location_of(&hit.entry, &node.location);
        node_inode(Arc::clone(&node.fs), Some(hit.entry), location, dir.cluster, hit.slot,
                   hit.nr_slots)
    }
}

impl InodeOps for FatOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let (node, dir) = Self::dir_of(inode)?;
        let hit = node.fs.volume.lock().find_entry(&dir, name).map_err(errno_to_vfs)?;
        Ok(Self::child(node, &dir, &hit))
    }

    fn dir_is_empty(&self, inode: &Inode) -> bool {
        let Ok((node, dir)) = Self::dir_of(inode) else { return true };
        let v = node.fs.volume.lock();
        let Ok(bytes) = v.directory_bytes(dir.cluster) else { return false };
        dir_is_empty(&bytes)
    }

    /// `mode` and the umask are read and discarded: this filesystem stores no
    /// permission bits, and what an entry presents with is the mount's
    /// `fmask=`/`dmask=` answer rather than anything the creator asked for.
    fn create(&self, inode: &Inode, name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        let (node, dir) = Self::dir_of(inode)?;
        let mut v = node.fs.volume.lock();
        let now = now_for(v.options());
        let hit = v.create_file(&dir, name, now).map_err(errno_to_vfs)?;
        drop(v);
        Ok(Self::child(node, &dir, &hit))
    }

    fn mkdir(&self, inode: &Inode, name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        let (node, dir) = Self::dir_of(inode)?;
        let mut v = node.fs.volume.lock();
        let now = now_for(v.options());
        let hit = v.create_dir(&dir, name, now).map_err(errno_to_vfs)?;
        drop(v);
        Ok(Self::child(node, &dir, &hit))
    }

    fn rmdir(&self, inode: &Inode, name: &str) -> KResult<()> {
        let (node, dir) = Self::dir_of(inode)?;
        let mut v = node.fs.volume.lock();
        let now = now_for(v.options());
        v.rmdir(&dir, name, now).map_err(errno_to_vfs)
    }

    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        let (node, dir) = Self::dir_of(inode)?;
        let mut v = node.fs.volume.lock();
        let now = now_for(v.options());
        v.unlink(&dir, name, now).map_err(errno_to_vfs)
    }

    fn rename(&self, inode: &Inode, old_name: &str, new_dir: &Inode, new_name: &str, flags: u32,
              _ctx: &CreateCtx) -> KResult<()> {
        let (node, from) = Self::dir_of(inode)?;
        let (target, to) = Self::dir_of(new_dir)?;
        // Both directories are on one volume by construction: a rename across
        // filesystems never reaches a backend.
        if !Arc::ptr_eq(&node.fs, &target.fs) { return Err(VfsError::Exdev); }
        let mut v = node.fs.volume.lock();
        let now = now_for(v.options());
        v.rename(&from, old_name, &to, new_name, flags, now).map_err(errno_to_vfs)
    }

    fn truncate(&self, inode: &Inode, len: u64) -> KResult<()> {
        let node = Self::node(inode)?;
        let entry = node.entry.ok_or(VfsError::Eisdir)?;
        let hit = DirEntry { name: String::new(), entry, slot: node.slot, nr_slots: node.nr_slots };
        let mut v = node.fs.volume.lock();
        let now = now_for(v.options());
        let mut cache = node.cache.lock();
        v.truncate_file_cached(node.container(), &hit, &mut cache, len, now)
            .map_err(errno_to_vfs)?;
        drop(cache);
        drop(v);
        inode.set_size(len);
        Ok(())
    }
}

impl FileOps for FatOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let node = FatOps::node(inode)?;
        let entry = node.entry.as_ref().ok_or(VfsError::Eisdir)?;
        let v = node.fs.volume.lock();
        let mut cache = node.cache.lock();
        v.read_file_cached(entry, &mut cache, off, buf).map_err(errno_to_vfs)
    }

    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let node = FatOps::node(inode)?;
        let entry = node.entry.ok_or(VfsError::Eisdir)?;
        // The name is not re-resolved: the record's own slot came with the
        // inode, so the write lands on the record this inode IS.
        let hit = DirEntry { name: String::new(), entry, slot: node.slot, nr_slots: node.nr_slots };
        let mut v = node.fs.volume.lock();
        let now = now_for(v.options());
        let mut cache = node.cache.lock();
        let size = v.write_file_cached(node.container(), &hit, &mut cache, off, buf, now)
            .map_err(errno_to_vfs)?;
        drop(cache);
        drop(v);
        inode.set_size(size);
        Ok(buf.len())
    }

    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let node = FatOps::node(inode)?;
        let entries = FatOps::entries(node)?;
        // `.` and `..` are ordinary entries on a FAT subdirectory but absent
        // from the root, so they are emitted here rather than trusted from the
        // medium — a root listing must still carry them.
        let self_ino = inode.ino();
        if ctx.pos == 0 && !ctx.emit(".", self_ino, FileType::Directory, 1) { return Ok(()); }
        if ctx.pos == 1 && !ctx.emit("..", self_ino, FileType::Directory, 2) { return Ok(()); }
        // Cursors 0/1 belong to the synthetic dots; 2 means the first medium
        // record. Every later cursor is the medium's canonical byte offset.
        let pos = if ctx.pos <= 2 { 0 } else { ctx.pos };
        for entry in &entries {
            if pos > entry.group_start() { continue; }
            // The medium's own dot entries would duplicate the two above.
            if entry.name == "." || entry.name == ".." { continue; }
            let location = ident::location_of(&entry.entry, &node.location);
            let ino = ident::inode_number(&location, Some(&entry.entry));
            let ftype = if entry.is_dir() { FileType::Directory } else { FileType::Regular };
            if !ctx.emit(&entry.name, ino, ftype, entry.next_pos()) { break; }
        }
        Ok(())
    }
}

/// Whether an inode names a directory this filesystem can read. Kept as a
/// function so the location rule has one owner. # C: O(1)
pub fn is_directory(location: &DirLocation) -> bool {
    !matches!(location, DirLocation::Entry { .. })
}
