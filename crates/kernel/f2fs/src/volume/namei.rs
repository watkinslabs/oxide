//! Creating, removing and renaming names.
//!
//! Every one of these changes TWO inodes — the directory and the thing named —
//! and the order matters. A new inode is written before its name is, so a
//! crash between the two leaves an unreachable inode rather than a name
//! pointing at nothing; and a name is removed before its inode's link count
//! drops, so the same crash leaves a link count too high rather than a live
//! name pointing at freed space. Both are the direction the reference chose,
//! and both are the direction a checker can repair.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::flags::*;
use crate::mode;
use crate::uapi::*;

use super::dnode::{put32, put64};
use super::Volume;

/// What a new inode is being made as.
#[derive(Clone, Debug)]
pub struct NewInode {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    /// The device a special file names, in the interface's encoding.
    pub rdev: u32,
    /// Seconds and nanoseconds every timestamp is stamped with.
    pub now: (u64, u32),
}

impl<S: SectorSource> Volume<S> {
    /// Build a fresh inode block for `ino`. # C: O(BLKSIZE)
    pub(crate) fn blank_inode(&self, ino: u32, spec: &NewInode, links: u32) -> Vec<u8> {
        let mut b = vec![0u8; BLKSIZE];
        let extra = if crate::features::has_extra_attr(self.sb.feature) {
            TOTAL_EXTRA_ATTR_SIZE
        } else {
            0
        };
        let inline = if extra > 0 { EXTRA_ATTR } else { 0 };
        b[I_INLINE] = inline;
        super::dnode::put16(&mut b, I_MODE, spec.mode);
        put32(&mut b, I_UID, spec.uid);
        put32(&mut b, I_GID, spec.gid);
        put32(&mut b, I_LINKS, links);
        put64(&mut b, I_SIZE, 0);
        put64(&mut b, I_BLOCKS, 1);
        for (sec_at, nsec_at) in
            [(I_ATIME, I_ATIME_NSEC), (I_CTIME, I_CTIME_NSEC), (I_MTIME, I_MTIME_NSEC)]
        {
            put64(&mut b, sec_at, spec.now.0);
            put32(&mut b, nsec_at, spec.now.1);
        }
        put32(&mut b, I_GENERATION, ino);
        if extra > 0 {
            super::dnode::put16(&mut b, I_EXTRA_ISIZE, extra as u16);
            let reserve = if crate::features::has_flexible_inline_xattr(self.sb.feature) {
                DEFAULT_INLINE_XATTR_ADDRS
            } else {
                0
            };
            super::dnode::put16(&mut b, I_INLINE_XATTR_SIZE, reserve as u16);
            put64(&mut b, I_CRTIME, spec.now.0);
            put32(&mut b, I_CRTIME_NSEC, spec.now.1);
        }
        b
    }

    /// Make a new inode of any kind and link it into `dir` as `name`.
    ///
    /// The one entry point for create, mkdir, symlink and mknod: they differ
    /// only in the mode, the initial contents and the link counts, and having
    /// four copies of the ordering above is how one of them ends up wrong.
    /// # C: O(depth) blocks
    pub fn create(&mut self, dir: u32, name: &[u8], spec: &NewInode, body: Option<&[u8]>)
        -> Result<u32, Errno> {
        self.writable_or_err()?;
        let parent = self.read_inode(dir)?;
        if mode::file_type(parent.mode) != vfs::FileType::Directory { return Err(Errno::Enotdir); }
        if self.lookup(&parent, dir, name).is_ok() { return Err(Errno::Eexist); }
        let ft = mode::file_type(spec.mode);
        let is_dir = ft == vfs::FileType::Directory;
        let ino = self.alloc_nid()?;
        let mut block = self.blank_inode(ino, spec, if is_dir { 2 } else { 1 });
        put32(&mut block, I_PINO, dir);
        let namelen = name.len().min(NAME_LEN);
        put32(&mut block, I_NAMELEN, namelen as u32);
        block[I_NAME..I_NAME + namelen].copy_from_slice(&name[..namelen]);
        if is_dir {
            block[I_INLINE] |= INLINE_DENTRY | INLINE_DATA | DATA_EXIST;
            put32(&mut block, I_CURRENT_DEPTH, 1);
        } else if self.opts.inline_data
            && matches!(ft, vfs::FileType::Regular | vfs::FileType::Symlink)
        {
            // A small file starts INSIDE its inode, which is where most files
            // on a real volume stay. The data-exists mark waits for the first
            // write: the region still holds the address array's old bytes.
            block[I_INLINE] |= INLINE_DATA;
        }
        if mode::has_rdev(spec.mode) {
            // The narrow slot stays zero so the wide one is what is read; the
            // narrow form cannot carry a minor past a byte.
            let base = OFFSET_OF_END_OF_I_EXT
                + le16(&block, I_EXTRA_ISIZE).unwrap_or(0) as usize;
            put32(&mut block, base + 4, spec.rdev);
        }
        self.write_node(ino, ino, block, self.node_kind(spec.mode))?;
        self.valid_inode_count += 1;
        self.charge_inode(ino)?;
        if is_dir { self.init_dir(ino, dir)?; }
        if let Some(bytes) = body { self.write_file(ino, 0, bytes)?; }
        // The name goes down last: a crash before it leaves an unreachable
        // inode, which a check reclaims, rather than a name pointing at
        // nothing, which it cannot.
        self.add_dentry(dir, name, ino, ftype_byte(spec.mode))?;
        if is_dir {
            let links = self.read_inode(dir)?.links.saturating_add(1);
            self.stamp_inode(dir, |b| put32(b, I_LINKS, links))?;
        }
        self.touch(dir, spec.now)?;
        Ok(ino)
    }

    /// Give a new directory its own two entries. # C: O(1 block)
    fn init_dir(&mut self, ino: u32, parent: u32) -> Result<(), Errno> {
        self.add_dentry(ino, b".", ino, FT_DIR)?;
        self.add_dentry(ino, b"..", parent, FT_DIR)
    }

    /// Remove a name. `expect_dir` says which of unlink and rmdir was asked
    /// for, and a mismatch is refused rather than silently done.
    /// # C: O(depth) blocks
    pub fn remove(&mut self, dir: u32, name: &[u8], expect_dir: bool, now: (u64, u32))
        -> Result<(), Errno> {
        self.writable_or_err()?;
        if name == b"." || name == b".." { return Err(Errno::Einval); }
        let parent = self.read_inode(dir)?;
        let hit = self.lookup(&parent, dir, name)?;
        let victim = self.read_inode(hit.ino)?;
        let victim_is_dir = mode::file_type(victim.mode) == vfs::FileType::Directory;
        if expect_dir && !victim_is_dir { return Err(Errno::Enotdir); }
        if !expect_dir && victim_is_dir { return Err(Errno::Eisdir); }
        if victim_is_dir && !self.dir_is_empty(&victim, hit.ino)? { return Err(Errno::Enotempty); }
        self.remove_dentry(dir, name)?;
        if victim_is_dir {
            // A directory's own two entries are its remaining links; both go
            // with it, and the parent loses the one its child held.
            self.free_inode(hit.ino)?;
            let links = self.read_inode(dir)?.links.saturating_sub(1).max(1);
            self.stamp_inode(dir, |b| put32(b, I_LINKS, links))?;
        } else {
            let links = victim.links.saturating_sub(1);
            if links == 0 {
                // The last name is gone, but a descriptor may still hold it.
                // Freeing it now would pull the blocks from under a reader;
                // parking it records the debt so a crash cannot lose it.
                self.drop_last_link(hit.ino, now)?;
            } else {
                self.stamp_inode(hit.ino, |b| {
                    put32(b, I_LINKS, links);
                    put64(b, I_CTIME, now.0);
                    put32(b, I_CTIME_NSEC, now.1);
                })?;
            }
        }
        self.touch(dir, now)
    }

    /// Give an existing file a second name. # C: O(depth) blocks
    pub fn link(&mut self, dir: u32, name: &[u8], ino: u32, now: (u64, u32))
        -> Result<(), Errno> {
        self.writable_or_err()?;
        let target = self.read_inode(ino)?;
        // A directory with two names is a loop the walk cannot escape, which
        // is why no filesystem allows one.
        if mode::file_type(target.mode) == vfs::FileType::Directory { return Err(Errno::Eperm); }
        let parent = self.read_inode(dir)?;
        if self.lookup(&parent, dir, name).is_ok() { return Err(Errno::Eexist); }
        self.add_dentry(dir, name, ino, ftype_byte(target.mode))?;
        let links = target.links.saturating_add(1);
        self.stamp_inode(ino, |b| {
            put32(b, I_LINKS, links);
            put64(b, I_CTIME, now.0);
            put32(b, I_CTIME_NSEC, now.1);
        })?;
        self.touch(dir, now)
    }

    /// Move a name, replacing an existing one if `flags` allows.
    /// # C: O(depth) blocks
    pub fn rename(&mut self, from: u32, old: &[u8], to: u32, new: &[u8], noreplace: bool,
                  now: (u64, u32)) -> Result<(), Errno> {
        self.writable_or_err()?;
        if old == b"." || old == b".." || new == b"." || new == b".." { return Err(Errno::Einval); }
        let from_inode = self.read_inode(from)?;
        let hit = self.lookup(&from_inode, from, old)?;
        let moving = self.read_inode(hit.ino)?;
        let moving_is_dir = mode::file_type(moving.mode) == vfs::FileType::Directory;
        let to_inode = self.read_inode(to)?;
        if let Ok(existing) = self.lookup(&to_inode, to, new) {
            if noreplace { return Err(Errno::Eexist); }
            if existing.ino == hit.ino { return Ok(()); }
            let victim = self.read_inode(existing.ino)?;
            let victim_is_dir = mode::file_type(victim.mode) == vfs::FileType::Directory;
            if victim_is_dir && !self.dir_is_empty(&victim, existing.ino)? {
                return Err(Errno::Enotempty);
            }
            if victim_is_dir != moving_is_dir {
                return Err(if victim_is_dir { Errno::Eisdir } else { Errno::Enotdir });
            }
            self.remove(to, new, victim_is_dir, now)?;
        }
        self.remove_dentry(from, old)?;
        self.add_dentry(to, new, hit.ino, hit.file_type)?;
        if moving_is_dir && from != to {
            // The moved directory's own second entry names its parent, and a
            // stale one sends every walk back to the wrong place.
            self.remove_dentry(hit.ino, b"..")?;
            self.add_dentry(hit.ino, b"..", to, FT_DIR)?;
            let up = self.read_inode(from)?.links.saturating_sub(1).max(1);
            self.stamp_inode(from, |b| put32(b, I_LINKS, up))?;
            let down = self.read_inode(to)?.links.saturating_add(1);
            self.stamp_inode(to, |b| put32(b, I_LINKS, down))?;
        }
        self.stamp_inode(hit.ino, |b| {
            put32(b, I_PINO, to);
            put64(b, I_CTIME, now.0);
            put32(b, I_CTIME_NSEC, now.1);
        })?;
        self.touch(from, now)?;
        if from != to { self.touch(to, now)?; }
        Ok(())
    }

    /// Stamp a directory's modification and change times. # C: O(1 block)
    pub(crate) fn touch(&mut self, ino: u32, now: (u64, u32)) -> Result<(), Errno> {
        self.stamp_inode(ino, |b| {
            put64(b, I_MTIME, now.0);
            put32(b, I_MTIME_NSEC, now.1);
            put64(b, I_CTIME, now.0);
            put32(b, I_CTIME_NSEC, now.1);
        })
    }

    /// Change an inode's permission bits and identity. # C: O(1 block)
    pub fn set_attr(&mut self, ino: u32, mode_bits: Option<u16>, owner: Option<(u32, u32)>,
                    now: (u64, u32)) -> Result<(), Errno> {
        self.writable_or_err()?;
        let cur = self.read_inode(ino)?.mode;
        self.stamp_inode(ino, |b| {
            if let Some(m) = mode_bits {
                super::dnode::put16(b, I_MODE, (cur & mode::S_IFMT) | (m & mode::PERM_MASK));
            }
            if let Some((uid, gid)) = owner {
                put32(b, I_UID, uid);
                put32(b, I_GID, gid);
            }
            put64(b, I_CTIME, now.0);
            put32(b, I_CTIME_NSEC, now.1);
        })
    }

    /// Change an inode's stored times. # C: O(1 block)
    pub fn set_times(&mut self, ino: u32, atime: (u64, u32), mtime: (u64, u32))
        -> Result<(), Errno> {
        self.writable_or_err()?;
        self.stamp_inode(ino, |b| {
            put64(b, I_ATIME, atime.0);
            put32(b, I_ATIME_NSEC, atime.1);
            put64(b, I_MTIME, mtime.0);
            put32(b, I_MTIME_NSEC, mtime.1);
        })
    }
}

/// The type byte a directory entry stores for a mode. # C: O(1)
pub fn ftype_byte(mode_word: u16) -> u8 {
    match mode::file_type(mode_word) {
        vfs::FileType::Directory => FT_DIR,
        vfs::FileType::Symlink => FT_SYMLINK,
        vfs::FileType::CharDev => FT_CHRDEV,
        vfs::FileType::BlockDev => FT_BLKDEV,
        vfs::FileType::Fifo => FT_FIFO,
        vfs::FileType::Socket => FT_SOCK,
        vfs::FileType::Regular => FT_REG_FILE,
    }
}

#[cfg(test)]
#[path = "../tests/namei.rs"]
mod tests;
