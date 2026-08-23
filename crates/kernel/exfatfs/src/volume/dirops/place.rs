//! Where a new entry set goes, and growing a directory to make room.
//!
//! A set must be CONSECUTIVE: its file entry, stream entry and name entries
//! are addressed by their distance from the first, so a run split across two
//! holes is not a set. Finding room means finding that many consecutive
//! entries that are unused or deleted — and if the directory has none, giving
//! it another cluster.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::dirent::kind::{class_of, EntryKind};
use crate::chain::Chain;
use crate::uapi::{DENTRY_BYTES, MAX_DENTRIES};

use super::{DirHandle, Volume};

/// The first run of `count` consecutive free entries in a directory's bytes.
///
/// An UNUSED entry ends the directory, so everything from the first one is
/// free — the run is not required to be already-deleted entries. A run that
/// reaches the end of the bytes is not a run: the entries past the end do not
/// exist yet.
/// # C: O(directory bytes)
pub fn find_free_run(bytes: &[u8], count: usize) -> Option<u64> {
    let slots = bytes.len() / DENTRY_BYTES;
    let mut run = 0usize;
    for index in 0..slots {
        let ty = bytes[index * DENTRY_BYTES];
        let free = matches!(class_of(ty), EntryKind::Unused | EntryKind::Deleted);
        run = if free { run + 1 } else { 0 };
        if run == count { return Some(((index + 1 - count) * DENTRY_BYTES) as u64); }
    }
    None
}

impl<S: SectorSource> Volume<S> {
    /// Reserve room for `count` consecutive entries in `dir`, growing it if
    /// there is none.
    ///
    /// Returns the offset AND the directory's clusters afterwards, which a
    /// grow changes: writing the new set through the pre-grow chain addresses
    /// a cluster the directory did not have a moment ago.
    /// # C: O(directory bytes)
    pub(crate) fn place_set(&mut self, dir: &DirHandle, count: usize)
        -> Result<(u64, Chain), Errno> {
        let chain = self.dir_chain(dir)?;
        let bytes = self.chain_bytes(&chain)?;
        if let Some(offset) = find_free_run(&bytes, count) { return Ok((offset, chain)); }
        let before = bytes.len() as u64;
        // A directory has a ceiling of its own, above the volume's: the format
        // admits eight million entries and no more.
        if (before / DENTRY_BYTES as u64) + count as u64 > MAX_DENTRIES {
            return Err(Errno::Enospc);
        }
        let grown = self.grow_directory(dir, count)?;
        let bytes = self.chain_bytes(&grown)?;
        let offset = find_free_run(&bytes, count).ok_or(Errno::Enospc)?;
        Ok((offset, grown))
    }

    /// Give a directory enough clusters for `count` more entries, cleared.
    ///
    /// The new clusters are zeroed BEFORE the directory's own entry admits
    /// them: an entry byte left from the cluster's last owner reads as a name,
    /// and a directory that grows into uncleared space gains files nobody
    /// created.
    /// # C: O(cluster bytes)
    pub(crate) fn grow_directory(&mut self, dir: &DirHandle, count: usize)
        -> Result<Chain, Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        let per = self.geo.cluster_bytes();
        let want = (count * DENTRY_BYTES) as u64;
        let more = self.geo.clusters_for(want).max(1);
        let mut chain = self.dir_chain(dir)?;
        let before = chain.size;
        self.alloc_clusters(&mut chain, more, false)?;
        for cluster in crate::chain::walk(&self.geo, &self.fat_reader(), &chain)
            .map_err(|_| self.fs_error("corrupt exFAT cluster chain"))?
            .into_iter().skip(before as usize) {
            self.zero_cluster(cluster)?;
        }
        // The directory's own set records how long it is; a grown directory
        // whose set still says the old length loses every entry past it on the
        // next mount.
        if let Some((parent, offset)) = self.own_of(dir)? {
            let mut whole = alloc::vec![0u8; DENTRY_BYTES];
            self.read_at(&parent, offset, &mut whole)?;
            if let Some(file) = crate::dirent::file::parse(&whole) {
                let span = file.set_len() * DENTRY_BYTES;
                let mut bytes = alloc::vec![0u8; span];
                self.read_at(&parent, offset, &mut bytes)?;
                let at = crate::uapi::ES_IDX_STREAM * DENTRY_BYTES;
                if let Some(mut stream) =
                    crate::dirent::stream::parse(&bytes[at..at + DENTRY_BYTES]) {
                    stream.start_cluster = chain.dir;
                    stream.flags = chain.flags;
                    stream.size = u64::from(chain.size) * per;
                    stream.valid_size = stream.size;
                    crate::dirent::stream::write(&stream, &mut bytes[at..at + DENTRY_BYTES]);
                    crate::dirent::set::reseal(&mut bytes);
                    self.write_at(&parent, offset, &bytes)?;
                }
            }
        } else {
            // The root has no set to record its length, so the mount's own
            // idea of it is the only record and must move with it.
            self.root = chain;
        }
        Ok(chain)
    }
}
