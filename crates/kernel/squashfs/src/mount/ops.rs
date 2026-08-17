//! The inode and file operations of a mounted image.
//!
//! One vector serves both: an inode and an open file need the same two things
//! here — the parsed inode and the volume's lock.
//!
//! Every mutating slot is left at its default, which answers `EPERM`, exactly
//! as a filesystem without the operation does. That is not an omission: the
//! format records no free space, no link count it could raise and no place to
//! put a new name, so there is nothing a write could mean.

use alloc::string::String;
use alloc::vec::Vec;

use vfs::xattr::XattrError;
use vfs::{DirContext, FileOps, FileType, Inode, InodeOps, InodeRef, KResult, VfsError};

use crate::volume::dir::SYNTHETIC_ENTRIES;
use crate::volume::Kind;

use super::node::{build, dirent_type, SquashNode};
use super::errno_to_vfs;

/// The operations, for every inode of this filesystem.
pub struct SquashOps;

impl SquashOps {
    /// The node behind an inode. # C: O(1)
    fn node(inode: &Inode) -> KResult<&SquashNode> {
        inode.private::<SquashNode>().ok_or(VfsError::Einval)
    }
}

impl InodeOps for SquashOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let n = Self::node(inode)?;
        let hit = {
            let v = n.fs.volume.lock();
            v.lookup(&n.node, name).map_err(errno_to_vfs)?
        };
        let child = n.fs.volume.lock().read_inode(hit.reference).map_err(errno_to_vfs)?;
        build(&n.fs, child)
    }

    fn dir_is_empty(&self, inode: &Inode) -> bool {
        let Ok(n) = Self::node(inode) else { return true };
        let v = n.fs.volume.lock();
        v.read_dir(&n.node).map(|e| e.is_empty()).unwrap_or(false)
    }

    fn readlink(&self, inode: &Inode) -> KResult<Vec<u8>> {
        let n = Self::node(inode)?;
        match &n.node.kind {
            Kind::Symlink { target } => Ok(target.clone()),
            _ => Err(VfsError::Einval),
        }
    }

    fn getxattr(&self, inode: &Inode, name: &str) -> Result<Vec<u8>, XattrError> {
        let n = Self::node(inode).map_err(XattrError::Fs)?;
        let v = n.fs.volume.lock();
        if !v.has_xattrs() { return Err(XattrError::NotSup); }
        let attrs = v.read_xattrs(n.node.xattr)
            .map_err(|e| XattrError::Fs(errno_to_vfs(e)))?;
        attrs.into_iter().find(|a| a.name == name).map(|a| a.value).ok_or(XattrError::NotFound)
    }

    fn listxattr(&self, inode: &Inode) -> Result<Vec<String>, XattrError> {
        let n = Self::node(inode).map_err(XattrError::Fs)?;
        let v = n.fs.volume.lock();
        if !v.has_xattrs() { return Err(XattrError::NotSup); }
        let attrs = v.read_xattrs(n.node.xattr)
            .map_err(|e| XattrError::Fs(errno_to_vfs(e)))?;
        Ok(attrs.into_iter().map(|a| a.name).collect())
    }
}

impl FileOps for SquashOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let n = SquashOps::node(inode)?;
        n.fs.volume.lock().read_file(&n.node, off, buf).map_err(errno_to_vfs)
    }

    /// The two names a listing does not store are emitted first, which is why
    /// every stored entry's position is three higher than its on-disk one.
    /// `..` reports the parent inode number the directory records, because
    /// there is no stored entry to take it from.
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let n = SquashOps::node(inode)?;
        let parent = match &n.node.kind {
            Kind::Dir { parent, .. } => *parent,
            _ => return Err(VfsError::Enotdir),
        };
        let self_ino = inode.ino();
        if ctx.pos == 0 && !ctx.emit(".", self_ino, FileType::Directory, 1) { return Ok(()); }
        if ctx.pos < SYNTHETIC_ENTRIES
            && !ctx.emit("..", u64::from(parent), FileType::Directory, SYNTHETIC_ENTRIES) {
            return Ok(());
        }
        let entries = {
            let v = n.fs.volume.lock();
            v.read_dir_from(&n.node, ctx.pos).map_err(errno_to_vfs)?
        };
        for entry in entries {
            if ctx.pos >= entry.next_pos { continue; }
            let ftype = dirent_type(entry.type_word).ok_or(VfsError::Eio)?;
            if !ctx.emit(&entry.name, u64::from(entry.ino), ftype, entry.next_pos) { break; }
        }
        Ok(())
    }
}
