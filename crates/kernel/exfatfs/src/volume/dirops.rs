//! Creating, deleting and renaming names.
//!
//! Every one of these is a rewrite of a RUN of entries, never of one. A set is
//! its file entry, its stream entry and its name entries together, and each
//! path here either writes the whole run and reseals its checksum or leaves
//! the directory exactly as it found it.
//!
//! Module manifest:
//! - `place`:  where a new set of N entries goes, and growing the directory.
//! - `rename`: moving a name, within a directory and across two.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::chain::Chain;
use crate::dirent::set;
use crate::name;
use crate::time::Stamp;
use crate::uapi::*;

use super::dir::DirEntry;
use super::Volume;

pub mod place;
pub mod rename;

/// A directory to operate in, named rather than cached.
///
/// A handle holds no cluster run. A directory GROWS — the root when it runs
/// out of entries, a subdirectory the same — and a cached run goes stale the
/// moment it does, so an operation through a stale handle addresses a cluster
/// the directory no longer ends at. Every path here resolves the run from the
/// medium at the moment it needs it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DirHandle {
    /// The volume's root, which no entry set describes.
    Root,
    /// A subdirectory, named by the directory holding its entry set and where
    /// in that directory the set sits.
    Child { parent: alloc::boxed::Box<DirHandle>, offset: u64 },
}

impl DirHandle {
    /// The root. # C: O(1)
    pub fn root() -> Self { DirHandle::Root }

    /// A subdirectory whose set sits at `offset` of `parent`. # C: O(1)
    pub fn child(parent: &DirHandle, offset: u64) -> Self {
        DirHandle::Child { parent: alloc::boxed::Box::new(parent.clone()), offset }
    }
}

impl<S: SectorSource> Volume<S> {
    /// The clusters a handle names, read fresh.
    /// # C: O(depth * directory bytes)
    pub fn dir_chain(&self, dir: &DirHandle) -> Result<Chain, Errno> {
        match dir {
            DirHandle::Root => Ok(self.root),
            DirHandle::Child { parent, offset } => {
                let (chain, _) = self.child_set(parent, *offset)?;
                Ok(chain)
            }
        }
    }

    /// Where a subdirectory's own entry set sits, and the run it names.
    /// # C: O(depth * directory bytes)
    fn child_set(&self, parent: &DirHandle, offset: u64) -> Result<(Chain, Chain), Errno> {
        let pchain = self.dir_chain(parent)?;
        let mut head = alloc::vec![0u8; DENTRY_BYTES];
        self.read_at(&pchain, offset, &mut head)?;
        let file = crate::dirent::file::parse(&head).ok_or(Errno::Eio)?;
        let span = file.set_len() * DENTRY_BYTES;
        let mut bytes = alloc::vec![0u8; span];
        self.read_at(&pchain, offset, &mut bytes)?;
        let parsed = set::parse(&bytes, offset).map_err(|_| Errno::Eio)?;
        if !parsed.is_dir() { return Err(Errno::Enotdir); }
        Ok((self.chain_of(&parsed), pchain))
    }

    /// The directory holding a handle's own set, and the offset of that set.
    /// The root has none. # C: O(depth * directory bytes)
    pub(crate) fn own_of(&self, dir: &DirHandle) -> Result<Option<(Chain, u64)>, Errno> {
        match dir {
            DirHandle::Root => Ok(None),
            DirHandle::Child { parent, offset } => Ok(Some((self.dir_chain(parent)?, *offset))),
        }
    }

    /// Write a set's fields back over the bytes it came from.
    ///
    /// The run is READ first and only the fields this implementation owns are
    /// replaced, so any benign secondary entry another system wrote — an
    /// access-control record, a vendor's own — survives a write it had nothing
    /// to do with. Rewriting the run wholesale silently discards them.
    /// # C: O(set bytes)
    pub fn write_entry_set(&self, entry: &DirEntry) -> Result<(), Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        let span = entry.set.entries * DENTRY_BYTES;
        let mut bytes = alloc::vec![0u8; span];
        self.read_at(&entry.dir, entry.set.offset, &mut bytes)?;
        crate::dirent::file::write(&entry.set.file, &mut bytes[..DENTRY_BYTES]);
        let at = ES_IDX_STREAM * DENTRY_BYTES;
        crate::dirent::stream::write(&entry.set.stream, &mut bytes[at..at + DENTRY_BYTES]);
        for (i, chunk) in entry.set.units.chunks(NAME_CHARS_PER_ENTRY).enumerate() {
            let at = (ES_IDX_FIRST_NAME + i) * DENTRY_BYTES;
            if at + DENTRY_BYTES > bytes.len() { break; }
            crate::dirent::stream::write_name(chunk, &mut bytes[at..at + DENTRY_BYTES]);
        }
        set::reseal(&mut bytes);
        self.write_at(&entry.dir, entry.set.offset, &bytes)
    }

    /// Create a name in `dir`, with the run and length it should start with.
    /// # C: O(directory bytes)
    fn create_named(&mut self, dir: &DirHandle, name: &str, attrs: u16, chain: Chain,
                    size: u64, now: Stamp) -> Result<DirEntry, Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        let uni = name::resolve(&self.upcase, name, self.opts.keep_last_dots,
                                name::Usage::Create)?;
        let dir_run = self.dir_chain(dir)?;
        if self.find_uni(&dir_run, &uni).is_ok() { return Err(Errno::Eexist); }
        let count = name::entry_count(uni.len())?;
        let start = if chain.is_empty() { 0 } else { chain.dir };
        let bytes = set::build(attrs, &uni.units, uni.hash, start, size, size, chain.flags,
                               now, now, crate::time::without_centiseconds(now))
            .map_err(|_| Errno::Einval)?;
        let (offset, grown) = self.place_set(dir, count)?;
        self.write_at(&grown, offset, &bytes)?;
        self.touch_directory(dir, now)?;
        let parsed = set::parse(&bytes, offset).map_err(|_| Errno::Eio)?;
        Ok(DirEntry { name: parsed.name(), set: parsed, dir: grown })
    }

    /// Create an empty file. # C: O(directory bytes)
    pub fn create_file(&mut self, dir: &DirHandle, name: &str, now: Stamp)
        -> Result<DirEntry, Errno> {
        // An empty file owns no clusters, so its run is recorded as chained:
        // a run of nothing marked contiguous claims cluster zero.
        self.create_named(dir, name, crate::dirent::file::new_attrs(false), Chain::empty(), 0, now)
    }

    /// Create a directory.
    ///
    /// A directory gets one cluster, ZEROED before its entry names it: an
    /// entry byte left over from the cluster's last owner reads as a name in a
    /// directory that is supposed to be empty. `zero_size_dir` asks for a
    /// directory with no cluster at all, which some tools expect.
    /// # C: O(directory bytes + cluster bytes)
    pub fn create_dir(&mut self, dir: &DirHandle, name: &str, now: Stamp)
        -> Result<DirEntry, Errno> {
        let mut chain = Chain::empty();
        let mut size = 0u64;
        if !self.opts.zero_size_dir {
            self.alloc_clusters(&mut chain, 1, true)?;
            self.zero_cluster(chain.dir)?;
            size = self.geo.cluster_bytes();
        }
        let attrs = crate::dirent::file::new_attrs(true);
        match self.create_named(dir, name, attrs, chain, size, now) {
            Ok(entry) => Ok(entry),
            Err(err) => {
                // The cluster was claimed before the name existed; a failure
                // after that would leak it.
                if !chain.is_empty() { let _ = self.free_chain(&chain); }
                Err(err)
            }
        }
    }

    /// Remove a name and release what it held. # C: O(directory bytes)
    pub fn unlink(&mut self, dir: &DirHandle, name: &str, now: Stamp) -> Result<(), Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        let chain = self.dir_chain(dir)?;
        let hit = self.find_entry(&chain, name)?;
        if hit.is_dir() { return Err(Errno::Eisdir); }
        let chains = self.remove_set_deferred(dir, &hit, now)?;
        for chain in &chains { self.free_chain(chain)?; }
        Ok(())
    }

    /// Remove a file's name but leave every allocation for the inode owner.
    /// # C: O(directory bytes)
    pub(crate) fn unlink_name(&mut self, dir: &DirHandle, name: &str, now: Stamp)
        -> Result<Vec<Chain>, Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        let chain = self.dir_chain(dir)?;
        let hit = self.find_entry(&chain, name)?;
        if hit.is_dir() { return Err(Errno::Eisdir); }
        self.remove_set_deferred(dir, &hit, now)
    }

    /// Remove an empty directory. # C: O(directory bytes)
    pub fn rmdir(&mut self, dir: &DirHandle, name: &str, now: Stamp) -> Result<(), Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        let chain = self.dir_chain(dir)?;
        let hit = self.find_entry(&chain, name)?;
        if !hit.is_dir() { return Err(Errno::Enotdir); }
        let inner = self.chain_of(&hit.set);
        if !inner.is_empty() && !self.dir_is_empty(&inner)? { return Err(Errno::Enotempty); }
        let chains = self.remove_set_deferred(dir, &hit, now)?;
        for chain in &chains { self.free_chain(chain)?; }
        Ok(())
    }

    /// Remove an empty directory's name but leave its allocation for the inode
    /// owner. # C: O(directory bytes)
    pub(crate) fn rmdir_name(&mut self, dir: &DirHandle, name: &str, now: Stamp)
        -> Result<Vec<Chain>, Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        let chain = self.dir_chain(dir)?;
        let hit = self.find_entry(&chain, name)?;
        if !hit.is_dir() { return Err(Errno::Enotdir); }
        let inner = self.chain_of(&hit.set);
        if !inner.is_empty() && !self.dir_is_empty(&inner)? { return Err(Errno::Enotempty); }
        self.remove_set_deferred(dir, &hit, now)
    }

    /// Mark a set deleted and return every allocation it held.
    ///
    /// The allocations of any BENIGN secondary entry go too: a vendor entry
    /// can carry an allocation of its own, and leaving it behind loses those
    /// clusters until a repair. The caller chooses whether the volume or the
    /// victim inode owns the returned chains.
    /// # C: O(set entries + run length)
    pub(crate) fn remove_set_deferred(&mut self, dir: &DirHandle, hit: &DirEntry, now: Stamp)
        -> Result<Vec<Chain>, Errno> {
        let span = hit.set.entries * DENTRY_BYTES;
        let mut bytes = alloc::vec![0u8; span];
        self.read_at(&hit.dir, hit.set.offset, &mut bytes)?;
        let extras: Vec<(u32, u64)> = bytes.chunks(DENTRY_BYTES)
            .filter_map(set::secondary_allocation)
            .collect();
        set::mark_deleted(&mut bytes);
        self.write_at(&hit.dir, hit.set.offset, &bytes)?;
        let mut chains = Vec::new();
        let chain = self.chain_of(&hit.set);
        if !chain.is_empty() { chains.push(chain); }
        for (start, size) in extras {
            let extra = self.chain_for(start, size, ALLOC_FAT_CHAIN);
            if !extra.is_empty() { chains.push(extra); }
        }
        self.touch_directory(dir, now)?;
        Ok(chains)
    }

    /// Stamp a directory's own entry set with the time it changed.
    ///
    /// The root has no such set, so nothing is stamped for it — which is what
    /// makes the root's reported times the epoch rather than an invented
    /// instant.
    /// # C: O(set bytes)
    pub(crate) fn touch_directory(&mut self, dir: &DirHandle, now: Stamp) -> Result<(), Errno> {
        let Some((parent, offset)) = self.own_of(dir)? else { return Ok(()) };
        let mut bytes = alloc::vec![0u8; DENTRY_BYTES];
        self.read_at(&parent, offset, &mut bytes)?;
        let Some(mut file) = crate::dirent::file::parse(&bytes) else { return Ok(()) };
        let span = file.set_len() * DENTRY_BYTES;
        let mut whole = alloc::vec![0u8; span];
        self.read_at(&parent, offset, &mut whole)?;
        file.modify = now;
        file.access = crate::time::without_centiseconds(now);
        crate::dirent::file::write(&file, &mut whole[..DENTRY_BYTES]);
        set::reseal(&mut whole);
        self.write_at(&parent, offset, &whole)
    }
}
