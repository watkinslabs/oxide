//! The inode and file operations of a mounted NTFS volume.
//!
//! `link` is absent, and unlike on FAT and exFAT that is a GAP rather than a
//! property of the format: NTFS counts hard links and every record carries as
//! many `$FILE_NAME` attributes as it has names. Adding one means inserting a
//! second index entry and raising the count, which is not done here yet — see
//! the ledger. The slot's default answers `EPERM`.

use alloc::sync::Arc;

use vfs::{CreateCtx, DirContext, FileOps, FileType, Inode, InodeOps, InodeRef, KResult,
          VfsError};

use crate::attrs;

use super::node::{node_inode, NtfsNode};
use super::{errno_to_vfs, now};

/// The operations, for every inode of this filesystem.
pub struct NtfsOps;

impl NtfsOps {
    /// The node behind an inode. # C: O(1)
    fn node(inode: &Inode) -> KResult<&NtfsNode> {
        inode.private::<NtfsNode>().ok_or(VfsError::Einval)
    }

    /// The node behind a DIRECTORY inode. # C: O(1)
    fn dir_of(inode: &Inode) -> KResult<&NtfsNode> {
        let node = Self::node(inode)?;
        if !node.info.is_dir { return Err(VfsError::Enotdir); }
        Ok(node)
    }

    /// Build the inode for a record. # C: O(record bytes)
    fn child(node: &NtfsNode, number: u64) -> KResult<InodeRef> {
        let info = node.fs.volume.lock().stat(number).map_err(errno_to_vfs)?;
        Ok(node_inode(Arc::clone(&node.fs), info))
    }
}

impl InodeOps for NtfsOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let node = Self::dir_of(inode)?;
        let hit = node.fs.volume.lock().find_entry(node.info.number, name)
            .map_err(errno_to_vfs)?;
        Self::child(node, hit.reference.number)
    }

    fn dir_is_empty(&self, inode: &Inode) -> bool {
        let Ok(node) = Self::dir_of(inode) else { return true };
        node.fs.volume.lock().dir_is_empty(node.info.number).unwrap_or(false)
    }

    /// `mode` is read and discarded: what a record presents with is the
    /// mount's `fmask=`/`dmask=` answer rather than anything the creator asked
    /// for, because the medium stores an access-control list and not a mode.
    fn create(&self, inode: &Inode, name: &str, _mode: u32, _ctx: &CreateCtx)
        -> KResult<InodeRef> {
        let node = Self::dir_of(inode)?;
        let hit = node.fs.volume.lock().create_file(node.info.number, name, now())
            .map_err(errno_to_vfs)?;
        Self::child(node, hit.reference.number)
    }

    fn mkdir(&self, inode: &Inode, name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        let node = Self::dir_of(inode)?;
        let hit = node.fs.volume.lock().create_dir(node.info.number, name, now())
            .map_err(errno_to_vfs)?;
        Self::child(node, hit.reference.number)
    }

    fn rmdir(&self, inode: &Inode, name: &str) -> KResult<()> {
        let node = Self::dir_of(inode)?;
        node.fs.volume.lock().rmdir(node.info.number, name, now()).map_err(errno_to_vfs)
    }

    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        let node = Self::dir_of(inode)?;
        node.fs.volume.lock().unlink(node.info.number, name, now()).map_err(errno_to_vfs)
    }

    fn rename(&self, inode: &Inode, old_name: &str, new_dir: &Inode, new_name: &str, flags: u32,
              _ctx: &CreateCtx) -> KResult<()> {
        let node = Self::dir_of(inode)?;
        let target = Self::dir_of(new_dir)?;
        if !Arc::ptr_eq(&node.fs, &target.fs) { return Err(VfsError::Exdev); }
        node.fs.volume.lock()
            .rename(node.info.number, old_name, target.info.number, new_name, flags, now())
            .map_err(errno_to_vfs)
    }

    fn truncate(&self, inode: &Inode, len: u64) -> KResult<()> {
        let node = Self::node(inode)?;
        node.fs.volume.lock().truncate_file(node.info.number, len, now())
            .map_err(errno_to_vfs)?;
        inode.set_size(len);
        Ok(())
    }

    fn readlink(&self, inode: &Inode) -> KResult<alloc::vec::Vec<u8>> {
        let node = Self::node(inode)?;
        let target = node.fs.volume.lock().read_link(node.info.number).map_err(errno_to_vfs)?;
        Ok(target.into_bytes())
    }
}

impl FileOps for NtfsOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let node = NtfsOps::node(inode)?;
        if node.info.is_dir { return Err(VfsError::Eisdir); }
        node.fs.volume.lock().read_file(node.info.number, off, buf).map_err(errno_to_vfs)
    }

    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let node = NtfsOps::node(inode)?;
        if node.info.is_dir { return Err(VfsError::Eisdir); }
        let size = node.fs.volume.lock().write_file(node.info.number, off, buf, now())
            .map_err(errno_to_vfs)?;
        inode.set_size(size);
        Ok(buf.len())
    }

    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let node = NtfsOps::dir_of(inode)?;
        let opts = node.fs.options();
        let entries = node.fs.volume.lock().read_dir(node.info.number).map_err(errno_to_vfs)?;
        // `.` and `..` are not entries of the index, so they are emitted here
        // or a listing has neither.
        let self_ino = inode.ino();
        if ctx.pos == 0 && !ctx.emit(".", self_ino, FileType::Directory, 1) { return Ok(()); }
        if ctx.pos == 1 && !ctx.emit("..", self_ino, FileType::Directory, 2) { return Ok(()); }
        let mut slot = 2u64;
        for entry in entries {
            // The volume's own metadata files carry the hidden and system
            // bits; listing them puts `$MFT` in the root of every mount.
            if attrs::hidden_from(entry.fname.attributes, &opts) { continue; }
            if ctx.pos <= slot {
                let ino = crate::ident::inode_number(entry.reference.number);
                let ftype = if entry.is_dir() { FileType::Directory } else { FileType::Regular };
                if !ctx.emit(&entry.name, ino, ftype, slot + 1) { break; }
            }
            slot += 1;
        }
        Ok(())
    }
}
