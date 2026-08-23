//! Moving a name: within a directory and between two.
//!
//! A rename on this filesystem is a new entry set written and the old one
//! marked deleted, because the name lives in the set and a set of a different
//! length occupies a different number of entries. What must NOT happen is the
//! file's clusters being freed with the old set: the run belongs to the file,
//! and the file is the same file.
//!
//! Order matters. The new set is written first and the old one deleted after,
//! so a failure in between leaves the name reachable twice rather than not at
//! all — and the reverse order loses the file outright.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::dirent::set;
use crate::name;
use crate::time::Stamp;
use crate::uapi::DENTRY_BYTES;

use super::{DirEntry, DirHandle, Volume};

/// `renameat2` flags this filesystem acts on.
pub const RENAME_NOREPLACE: u32 = 1;
pub const RENAME_EXCHANGE: u32 = 2;
pub const RENAME_WHITEOUT: u32 = 4;

impl<S: SectorSource> Volume<S> {
    /// Move `old_name` in `from` to `new_name` in `to`.
    /// # C: O(directory bytes)
    pub fn rename(&mut self, from: &DirHandle, old_name: &str, to: &DirHandle, new_name: &str,
                  flags: u32, now: Stamp) -> Result<(), Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        // A whiteout has no representation here: this filesystem stores no
        // character-device entry to leave behind.
        if flags & RENAME_WHITEOUT != 0 { return Err(Errno::Einval); }
        if flags & RENAME_NOREPLACE != 0 && flags & RENAME_EXCHANGE != 0 {
            return Err(Errno::Einval);
        }
        let from_chain = self.dir_chain(from)?;
        let to_chain = self.dir_chain(to)?;
        let source = self.find_entry(&from_chain, old_name)?;
        let target = self.find_entry(&to_chain, new_name).ok();

        if flags & RENAME_EXCHANGE != 0 {
            let target = target.ok_or(Errno::Enoent)?;
            return self.exchange(from, &source, to, &target, now);
        }
        if let Some(target) = &target {
            if flags & RENAME_NOREPLACE != 0 { return Err(Errno::Eexist); }
            // A name being replaced must be the same KIND of thing, and a
            // directory being replaced must be empty — replacing a populated
            // one would strand every name inside it.
            if target.is_dir() != source.is_dir() {
                return Err(if target.is_dir() { Errno::Eisdir } else { Errno::Enotdir });
            }
            if target.is_dir() {
                let inner = self.chain_of(&target.set);
                if !inner.is_empty() && !self.dir_is_empty(&inner)? { return Err(Errno::Enotempty); }
            }
        }

        // Renaming a name onto itself in the same directory is a no-op, and
        // must not delete it — which is what writing then deleting would do.
        if from_chain == to_chain {
            if let Some(target) = &target {
                if target.set.offset == source.set.offset { return Ok(()); }
            }
        }

        let placed = self.write_moved(to, &source, new_name, now)?;
        if let Some(target) = &target { self.detach_set(target)?; self.reclaim(target)?; }
        self.detach_set(&source)?;
        self.touch_directory(from, now)?;
        if from != to { self.touch_directory(to, now)?; }
        let _ = placed;
        Ok(())
    }

    /// Write `source`'s set under a new name in `to`, keeping its run.
    /// # C: O(directory bytes)
    fn write_moved(&mut self, to: &DirHandle, source: &DirEntry, new_name: &str, now: Stamp)
        -> Result<DirEntry, Errno> {
        let uni = name::resolve(&self.upcase, new_name, self.opts.keep_last_dots,
                                name::Usage::Create)?;
        let count = name::entry_count(uni.len())?;
        let stream = source.set.stream;
        let bytes = set::build(source.set.file.attr, &uni.units, uni.hash, stream.start_cluster,
                               stream.size, stream.valid_size, stream.flags,
                               source.set.file.create, now,
                               crate::time::without_centiseconds(now))
            .map_err(|_| Errno::Einval)?;
        let (offset, grown) = self.place_set(to, count)?;
        self.write_at(&grown, offset, &bytes)?;
        let parsed = set::parse(&bytes, offset).map_err(|_| Errno::Eio)?;
        Ok(DirEntry { name: parsed.name(), set: parsed, dir: grown })
    }

    /// Mark a set deleted WITHOUT releasing what it points at.
    ///
    /// This is the half of a removal a rename needs: the name goes, the file
    /// stays. Reusing the removal path here frees the clusters the renamed
    /// file is still using.
    /// # C: O(set bytes)
    fn detach_set(&mut self, entry: &DirEntry) -> Result<(), Errno> {
        let span = entry.set.entries * DENTRY_BYTES;
        let mut bytes = alloc::vec![0u8; span];
        self.read_at(&entry.dir, entry.set.offset, &mut bytes)?;
        set::mark_deleted(&mut bytes);
        self.write_at(&entry.dir, entry.set.offset, &bytes)
    }

    /// Release what a replaced name held. # C: O(run length)
    fn reclaim(&mut self, entry: &DirEntry) -> Result<(), Errno> {
        let chain = self.chain_of(&entry.set);
        if chain.is_empty() { return Ok(()); }
        self.free_chain(&chain)
    }

    /// Swap two names, each keeping its own run.
    ///
    /// Both new sets are written before either old one is deleted, so a
    /// failure part-way leaves both files reachable under some name.
    /// # C: O(directory bytes)
    fn exchange(&mut self, from: &DirHandle, source: &DirEntry, to: &DirHandle,
                target: &DirEntry, now: Stamp) -> Result<(), Errno> {
        let source_name = source.name.clone();
        let target_name = target.name.clone();
        self.write_moved(to, source, &target_name, now)?;
        self.write_moved(from, target, &source_name, now)?;
        self.detach_set(source)?;
        self.detach_set(target)?;
        self.touch_directory(from, now)?;
        if from != to { self.touch_directory(to, now)?; }
        Ok(())
    }
}
