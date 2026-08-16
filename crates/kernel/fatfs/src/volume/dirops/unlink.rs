//! Removing a name, and the emptiness a directory must have first.
//!
//! The order is the reference's, and it is the order that makes an interrupted
//! deletion recoverable: the NAME goes first, then the clusters it reached.
//! Between the two the volume holds a chain nothing points at — a lost chain,
//! which every checker reclaims. The reverse order holds a live name pointing
//! at clusters the table calls free, which the next allocation hands to
//! another file, and the two then share the same bytes.
//!
//! A directory's emptiness is checked BEFORE its name is looked up, exactly as
//! the reference checks it: a non-empty directory must fail without having
//! touched anything.

use syscall::errno::Errno;

use crate::namei::dir_is_empty;
use crate::time::FatTime;

use super::super::{DirEntry, SectorSource, Volume};
use super::DirHandle;

impl<S: SectorSource> Volume<S> {
    /// Remove the file `name` names.
    ///
    /// `EISDIR` for a directory: the caller wanted the other operation, and
    /// removing a directory's record here would leave everything inside it
    /// unreachable and still marked in use.
    /// # C: O(directory bytes + chain length)
    pub fn unlink(&mut self, dir: &DirHandle, name: &str, now: FatTime) -> Result<(), Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        let hit = self.find_entry(dir, name)?;
        if hit.is_dir() { return Err(Errno::Eisdir); }
        self.remove_group(dir, hit.group_start(), hit.nr_slots)?;
        self.release_chain(hit.entry.cluster)?;
        self.touch_dir(dir, now)
    }

    /// Remove the directory `name` names, which must hold nothing.
    /// # C: O(directory bytes + chain length)
    pub fn rmdir(&mut self, dir: &DirHandle, name: &str, now: FatTime) -> Result<(), Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        let hit = self.find_entry(dir, name)?;
        if !hit.is_dir() { return Err(Errno::Enotdir); }
        self.require_empty(&hit)?;
        self.remove_group(dir, hit.group_start(), hit.nr_slots)?;
        self.release_chain(hit.entry.cluster)?;
        self.touch_dir(dir, now)
    }

    /// `ENOTEMPTY` unless the directory `hit` names holds only `.` and `..`.
    ///
    /// Freed records, long-name slots and a volume label do not count against
    /// it: none of them is a name anything can open.
    /// # C: O(directory bytes)
    pub(crate) fn require_empty(&self, hit: &DirEntry) -> Result<(), Errno> {
        let bytes = self.directory_bytes(Some(hit.entry.cluster))?;
        if dir_is_empty(&bytes) { return Ok(()); }
        Err(Errno::Enotempty)
    }
}
