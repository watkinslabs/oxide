//! An inode with no name at all.
//!
//! `O_TMPFILE` asks for a file that exists, can be written and read, and is
//! reachable through nothing but the handle that created it. On the medium that
//! is an inode with a link count of zero — and a link count of zero is exactly
//! what a checker reclaims, so the inode has to be parked on the orphan list
//! before anything can crash. That list is the SAME one an unlink of an open
//! file uses: a second register of unnamed inodes could disagree with it, and
//! the one in the checkpoint is the one a later mount reads.
//!
//! The whiteout a `RENAME_WHITEOUT` leaves behind is the same object at the
//! start of its life, which is why it is made here too — it is created
//! nameless and then given the name the rename vacated.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::flags::{DATA_EXIST, INLINE_DATA, INLINE_DENTRY};
use crate::mode;
use crate::uapi::*;

use super::dnode::put32;
use super::namei::NewInode;
use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Make an inode under `dir` that no name reaches, and report its number.
    ///
    /// `dir` decides nothing about where the inode lives — every node of this
    /// filesystem is reached through the same table — but it is what the
    /// request named, so it is checked: a caller asking for a temporary file
    /// inside a regular file has asked for something that cannot exist.
    ///
    /// The order is the one a crash has to survive. The reservation on the
    /// orphan list is taken FIRST, because a list with no room left is the one
    /// failure that would otherwise be discovered after the inode was already
    /// written and unreachable. Then the inode itself, and only then is the
    /// reservation spent — so a failure in between hands the reservation back
    /// rather than leaving a slot promised to nobody.
    /// # C: O(1 block)
    pub fn tmpfile(&mut self, dir: u32, spec: &NewInode) -> Result<u32, Errno> {
        self.writable_or_err()?;
        let parent = self.read_inode(dir)?;
        if mode::file_type(parent.mode) != vfs::FileType::Directory { return Err(Errno::Enotdir); }
        // A directory with no name has no way to hold its own second entry
        // pointing anywhere useful, and nothing could ever link it into a tree.
        if mode::file_type(spec.mode) == vfs::FileType::Directory { return Err(Errno::Eisdir); }
        if self.orphans_full() { return Err(Errno::Enospc); }
        let ino = self.alloc_nid()?;
        // Zero links from the moment it is written. An inode that claimed one
        // and then had it taken away is reachable to anything that reads the
        // medium in between, and a crash in that window leaves a file a checker
        // has no reason to reclaim.
        let mut block = self.blank_inode(ino, spec, 0);
        put32(&mut block, I_PINO, dir);
        // No name, so no name length: the field a chain replay reads to restore
        // a directory entry says there is nothing to restore, which is the
        // truth for a file that never had an entry.
        put32(&mut block, I_NAMELEN, 0);
        // The compression policy is offered the parent's setting and NOT a
        // name, because there is no name to describe the bytes with.
        let compressed = self.stamp_new_compress(&mut block, parent.flags, false, None);
        if !compressed && self.opts.inline_data
            && matches!(mode::file_type(spec.mode), vfs::FileType::Regular) {
            block[I_INLINE] |= INLINE_DATA;
        }
        if mode::has_rdev(spec.mode) {
            let base = OFFSET_OF_END_OF_I_EXT
                + le16(&block, I_EXTRA_ISIZE).unwrap_or(0) as usize;
            put32(&mut block, base + 4, spec.rdev);
        }
        debug_assert!(block[I_INLINE] & INLINE_DENTRY == 0);
        debug_assert!(block[I_INLINE] & DATA_EXIST == 0);
        self.write_node(ino, ino, block, self.node_kind(spec.mode))?;
        self.valid_inode_count += 1;
        if let Err(e) = self.charge_inode(ino) { let _ = self.free_inode(ino); return Err(e); }
        // Parked LAST, after every step that can fail: the list is what a later
        // mount reclaims from, and a number on it that was never written is a
        // free of an inode belonging to whoever holds that number next.
        if let Err(e) = self.add_orphan(ino) { let _ = self.free_inode(ino); return Err(e); }
        // Held open, so the close that follows the last handle frees it here
        // rather than leaving the reclaim to the next mount.
        self.open_inode(ino);
        // The parent's times move: the reference stamps the directory a
        // temporary file was created under, and a backup reading only the
        // directory otherwise sees no change from a volume that gained a file.
        self.touch(dir, spec.now)?;
        Ok(ino)
    }

    /// Whether the orphan list has room for one more.
    ///
    /// Asked BEFORE an inode is taken, which is the whole reason it is separate
    /// from the parking itself: a list that is full is a refusal the caller can
    /// act on, where the same refusal after the inode exists is an inode that
    /// has to be unwound.
    /// # C: O(1)
    pub(crate) fn orphans_full(&self) -> bool {
        self.orphans.len() as u64 >= self.max_orphans()
    }
}

#[cfg(test)]
#[path = "../tests/tmpfile.rs"]
mod tests;
