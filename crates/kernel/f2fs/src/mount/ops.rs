//! The inode and file operations of a mounted volume.
//!
//! One vector serves both: every operation needs the same two things, the
//! inode this object was built from and the volume's lock.
//!
//! The mutating operations are absent. This mount is READ-ONLY, so their
//! defaults answer for them — a mount that offered them and failed at the
//! first byte would be worse than one that says so at the interface.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::xattr::XattrError;
use vfs::{DirContext, FileType, Inode, InodeOps, InodeRef, FileOps, KResult, VfsError};

use crate::flags::*;
use crate::mode;

use super::node::{node_inode, F2fsNode};
use super::errno_to_vfs;

/// The operations, for every inode of this filesystem.
pub struct F2fsOps;

impl F2fsOps {
    /// The node behind an inode. # C: O(1)
    fn node(inode: &Inode) -> KResult<&F2fsNode> {
        inode.private::<F2fsNode>().ok_or(VfsError::Einval)
    }

    /// The node behind a DIRECTORY inode. # C: O(1)
    fn dir_of(inode: &Inode) -> KResult<&F2fsNode> {
        let node = Self::node(inode)?;
        if mode::file_type(node.inode.mode) != FileType::Directory {
            return Err(VfsError::Enotdir);
        }
        Ok(node)
    }
}

impl InodeOps for F2fsOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let node = Self::dir_of(inode)?;
        let hit = {
            let v = node.fs.volume.lock();
            v.lookup(&node.inode, node.ino, name.as_bytes()).map_err(errno_to_vfs)?
        };
        node_inode(Arc::clone(&node.fs), hit.ino)
    }

    fn dir_is_empty(&self, inode: &Inode) -> bool {
        let Ok(node) = Self::dir_of(inode) else { return true };
        let v = node.fs.volume.lock();
        v.dir_is_empty(&node.inode, node.ino).unwrap_or(false)
    }

    fn readlink(&self, inode: &Inode) -> KResult<Vec<u8>> {
        let node = Self::node(inode)?;
        if mode::file_type(node.inode.mode) != FileType::Symlink { return Err(VfsError::Einval); }
        let v = node.fs.volume.lock();
        v.read_link(&node.inode, node.ino).map_err(errno_to_vfs)
    }

    fn getxattr(&self, inode: &Inode, name: &str) -> Result<Vec<u8>, XattrError> {
        let node = Self::node(inode).map_err(XattrError::Fs)?;
        let v = node.fs.volume.lock();
        v.get_xattr(&node.inode, node.ino, name).map_err(xattr_errno)
    }

    fn listxattr(&self, inode: &Inode) -> Result<Vec<String>, XattrError> {
        let node = Self::node(inode).map_err(XattrError::Fs)?;
        let bytes = {
            let v = node.fs.volume.lock();
            v.list_xattr(&node.inode, node.ino).map_err(xattr_errno)?
        };
        Ok(split_names(&bytes))
    }
}

impl FileOps for F2fsOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let node = F2fsOps::node(inode)?;
        if mode::file_type(node.inode.mode) == FileType::Directory {
            return Err(VfsError::Eisdir);
        }
        let v = node.fs.volume.lock();
        v.read_file(&node.inode, node.ino, off, buf).map_err(errno_to_vfs)
    }

    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let node = F2fsOps::dir_of(inode)?;
        let entries = {
            let v = node.fs.volume.lock();
            v.read_dir(&node.inode, node.ino).map_err(errno_to_vfs)?
        };
        // This filesystem STORES `.` and `..` as ordinary entries, so they are
        // emitted from the listing rather than synthesised: synthesising them
        // on top of the stored pair would report each twice.
        for (i, e) in entries.iter().enumerate() {
            let slot = i as u64;
            if ctx.pos > slot { continue; }
            let name = alloc::string::String::from_utf8_lossy(&e.name);
            if !ctx.emit(&name, u64::from(e.ino), vfs_type(e.file_type), slot + 1) { break; }
        }
        Ok(())
    }
}

/// A stored type byte as the interface's type.
///
/// An unknown byte presents as a regular file rather than being dropped: the
/// entry exists and hiding it would make the name unreachable, while the
/// inode it points at states its own real type.
/// # C: O(1)
pub fn vfs_type(ft: u8) -> FileType {
    match ft {
        FT_DIR => FileType::Directory,
        FT_CHRDEV => FileType::CharDev,
        FT_BLKDEV => FileType::BlockDev,
        FT_FIFO => FileType::Fifo,
        FT_SOCK => FileType::Socket,
        FT_SYMLINK => FileType::Symlink,
        _ => FileType::Regular,
    }
}

/// # C: O(1)
fn xattr_errno(e: syscall::errno::Errno) -> XattrError {
    match e {
        syscall::errno::Errno::Enodata => XattrError::NotFound,
        syscall::errno::Errno::Eopnotsupp => XattrError::NotSup,
        other => XattrError::Fs(errno_to_vfs(other)),
    }
}

/// The zero-terminated name list as separate names. # C: O(bytes)
pub fn split_names(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

#[cfg(test)]
#[path = "../tests/ops.rs"]
mod tests;
