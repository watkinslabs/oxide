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
    ///
    /// `named` says whether the operation doing the creating means the name to
    /// describe the file's future contents, which is what the compression
    /// policy reads it as. Ordinary file creation does; making a device node,
    /// a directory or a symbolic link does not.
    /// # C: O(depth) blocks
    pub fn make(self: &Arc<Self>, dir: u32, name: &str, mode_word: u16, uid: u32, gid: u32,
                rdev: u32, body: Option<&[u8]>, named: bool) -> KResult<InodeRef> {
        let spec = NewInode { mode: mode_word, uid, gid, rdev, now: now() };
        let ino = {
            let mut v = self.volume_now();
            let n = name.as_bytes();
            let r = if named { v.create_named(dir, n, &spec, body) }
                    else { v.create(dir, n, &spec, body) };
            r.map_err(errno_to_vfs)?
        };
        // Every operation that used space asks, before it returns, whether the
        // volume can still serve the next one. Asking afterwards is the point:
        // the caller has its result, so a clean or a checkpoint here delays
        // this operation rather than failing it.
        self.balance(true)?;
        node_inode(Arc::clone(self), ino)
    }

    /// Remove a name. # C: O(depth) blocks
    pub fn remove(self: &Arc<Self>, dir: u32, name: &str, expect_dir: bool) -> KResult<()> {
        let out = self.volume
            .lock()
            .remove(dir, name.as_bytes(), expect_dir, now())
            .map_err(errno_to_vfs)?;
        // The volume parked the inode and could go no further: what it cannot
        // see is whether anything still holds the file. Settling that is the
        // other half of the removal, and skipping it leaves an inode nothing can
        // reach still holding its blocks for the life of the mount.
        self.after_remove(out)?;
        self.balance(true)
    }

    /// Give an existing inode a second name. # C: O(depth) blocks
    pub fn link(self: &Arc<Self>, dir: u32, name: &str, ino: u32) -> KResult<()> {
        self.volume_now().link(dir, name.as_bytes(), ino, now()).map_err(errno_to_vfs)?;
        self.balance(true)
    }

    /// Move a name, in whichever of the three forms `flags` asks for.
    ///
    /// The flags are carried through rather than reduced to a boolean: a form
    /// this filesystem cannot do has to be refused, and a request narrowed to
    /// "replace or not" on the way down cannot be.
    /// # C: O(depth) blocks
    pub fn rename(self: &Arc<Self>, from: u32, old: &str, to: u32, new: &str, flags: u32,
                  owner: (u32, u32)) -> KResult<()> {
        let r = crate::volume::Rename {
            from, old: old.as_bytes(), to, new: new.as_bytes(), flags, owner, now: now(),
        };
        let replaced = self.volume.lock().rename(&r).map_err(errno_to_vfs)?;
        // A move onto an existing name is a removal of that name, and owes the
        // inode behind it exactly what an unlink owes: its cached link count,
        // and an eviction if nothing holds it. Left out, a `mv` over an open
        // file leaks the file it replaced.
        if let Some(out) = replaced { self.after_remove(out)?; }
        self.balance(true)
    }

    /// Make an inode under `dir` that no name reaches. # C: O(1 block)
    pub fn tmpfile(self: &Arc<Self>, dir: u32, mode_word: u16, uid: u32, gid: u32)
        -> KResult<InodeRef> {
        let spec = NewInode { mode: mode_word, uid, gid, rdev: 0, now: now() };
        let ino = self.volume_now().tmpfile(dir, &spec).map_err(errno_to_vfs)?;
        self.balance(true)?;
        let inode = node_inode(Arc::clone(self), ino)?;
        // An unnamed file's link count is ZERO and has to present as zero: that
        // is how a caller tells a temporary file from an ordinary one, and how
        // it knows the file disappears when the handle does.
        inode.set_nlink(0);
        Ok(inode)
    }

    /// Write into a file, reporting the bytes that landed. # C: O(bytes)
    pub fn write(self: &Arc<Self>, ino: u32, off: u64, data: &[u8]) -> KResult<usize> {
        let n = self.volume_now().write_file(ino, off, data).map_err(errno_to_vfs)?;
        // Both of these act on state the write just changed, and both are here
        // rather than inside the writer because the guard above is dropped by
        // the end of the statement that took it. Balancing writes back when the
        // machine is over its dirty limit, which re-enters this mount; a
        // process that could dirty without bound would otherwise outrun every
        // flusher on the box.
        self.balance_data(ino);
        self.balance(true)?;
        Ok(n)
    }

    /// Shorten or extend a file. # C: O(blocks released)
    pub fn truncate(self: &Arc<Self>, ino: u32, len: u64) -> KResult<()> {
        self.volume_now().truncate_file(ino, len).map_err(errno_to_vfs)?;
        self.balance(true)
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
