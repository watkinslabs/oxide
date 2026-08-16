//! The mutating operations, and the one clock they all read.
//!
//! Every operation takes ONE reading of the wall clock and stamps every field
//! it touches with it. Taking a fresh reading per field lets a file's
//! modification time and its parent directory's disagree by the width of the
//! work between them, which every incremental backup then reports as a change
//! that did not happen.

use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{FileType, InodeRef, KResult, VfsError};

use crate::mode;
use crate::volume::NewInode;

use super::node::node_inode;
use super::{errno_to_vfs, F2fs};

/// The current instant, as the medium stores it. # C: O(1)
pub fn now() -> (u64, u32) {
    let t = vfs::timespec::Timespec64::from_clock_ns(vfs::inode_times::realtime_now_ns());
    (t.sec.max(0) as u64, t.nsec)
}

impl F2fs {
    /// Make a new inode of `kind` under `dir`, and hand back its inode.
    ///
    /// The mode carries the type; `body` is the initial contents, which a
    /// symbolic link uses for its target and nothing else does.
    /// # C: O(depth) blocks
    pub fn make(self: &Arc<Self>, dir: u32, name: &str, mode_word: u16, uid: u32, gid: u32,
                rdev: u32, body: Option<&[u8]>) -> KResult<InodeRef> {
        let spec = NewInode { mode: mode_word, uid, gid, rdev, now: now() };
        let ino = {
            let mut v = self.volume.lock();
            v.create(dir, name.as_bytes(), &spec, body).map_err(errno_to_vfs)?
        };
        node_inode(Arc::clone(self), ino)
    }

    /// Remove a name. # C: O(depth) blocks
    pub fn remove(&self, dir: u32, name: &str, expect_dir: bool) -> KResult<()> {
        self.volume
            .lock()
            .remove(dir, name.as_bytes(), expect_dir, now())
            .map_err(errno_to_vfs)
    }

    /// Give an existing inode a second name. # C: O(depth) blocks
    pub fn link(&self, dir: u32, name: &str, ino: u32) -> KResult<()> {
        self.volume.lock().link(dir, name.as_bytes(), ino, now()).map_err(errno_to_vfs)
    }

    /// Move a name. # C: O(depth) blocks
    pub fn rename(&self, from: u32, old: &str, to: u32, new: &str, noreplace: bool)
        -> KResult<()> {
        self.volume
            .lock()
            .rename(from, old.as_bytes(), to, new.as_bytes(), noreplace, now())
            .map_err(errno_to_vfs)
    }

    /// Write into a file, reporting the bytes that landed. # C: O(bytes)
    pub fn write(&self, ino: u32, off: u64, data: &[u8]) -> KResult<usize> {
        self.volume.lock().write_file(ino, off, data).map_err(errno_to_vfs)
    }

    /// Shorten or extend a file. # C: O(blocks released)
    pub fn truncate(&self, ino: u32, len: u64) -> KResult<()> {
        self.volume.lock().truncate_file(ino, len).map_err(errno_to_vfs)
    }

    /// Read a whole file, for a caller with no open file. # C: O(bytes)
    pub fn read_all(&self, ino: u32) -> KResult<Vec<u8>> {
        let v = self.volume.lock();
        let inode = v.read_inode(ino).map_err(errno_to_vfs)?;
        v.read_whole(&inode, ino).map_err(errno_to_vfs)
    }

    /// Push everything this mount has changed to the medium. # C: O(dirty)
    pub fn sync(&self) -> KResult<()> { self.checkpoint() }
}

/// The mode word a creation asks for, with the type the caller meant.
/// # C: O(1)
pub fn mk_mode(ftype: FileType, perm: u32) -> u16 {
    let t = match ftype {
        FileType::Directory => mode::S_IFDIR,
        FileType::Symlink => mode::S_IFLNK,
        FileType::CharDev => mode::S_IFCHR,
        FileType::BlockDev => mode::S_IFBLK,
        FileType::Fifo => mode::S_IFIFO,
        FileType::Socket => mode::S_IFSOCK,
        FileType::Regular => mode::S_IFREG,
    };
    t | (perm as u16 & mode::PERM_MASK)
}

/// The type a `mknod` mode word names, refusing one that names nothing.
/// # C: O(1)
pub fn mknod_type(mode_word: u32) -> KResult<FileType> {
    let ft = mode::file_type(mode_word as u16);
    // A mode with no type field at all means a regular file, which is what
    // `mknod(2)` creates for a zero type.
    if mode_word as u16 & mode::S_IFMT == 0 { return Ok(FileType::Regular); }
    match ft {
        FileType::Directory | FileType::Symlink => Err(VfsError::Einval),
        other => Ok(other),
    }
}

#[cfg(test)]
#[path = "../tests/mkmode.rs"]
mod tests;
