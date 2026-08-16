//! Carrying the two passes out against a mounted volume.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::{BLKSIZE, NULL_ADDR};
use crate::volume::dnode::Holder;
use crate::volume::Volume;

use super::plan::{self, Facts, Survey};

impl<S: SectorSource> Volume<S> {
    /// Rewrite the blocks of `ino` in `[start, start+len)` so they land
    /// contiguously, and report how many BYTES were moved.
    ///
    /// Zero is a success, not a refusal: a range that is already one run, or
    /// that holds nothing, is defragmented by definition and the caller is
    /// told nothing moved rather than given an error it would have to
    /// special-case.
    /// # C: O(blocks in the range)
    pub fn defragment_range(&mut self, ino: u32, start: u64, len: u64) -> Result<u64, Errno> {
        self.writable_or_err()?;
        let inode = self.read_inode(ino)?;
        let blk = BLKSIZE as u64;
        let first = start / blk;
        // The range stops at the end of the file however far the caller asked:
        // blocks past the end do not exist, and rewriting them would allocate
        // where the file has nothing.
        let end = start.saturating_add(len).min(u64::MAX - blk + 1) / blk;
        let end = end.min(inode.size.div_ceil(blk));
        if first >= end { return Ok(0); }

        let facts = Facts {
            compress_released: inode.has(crate::flags::COMPRESS_RELEASED),
            atomic: self.is_atomic_file(ino),
            pinned: crate::pin::state::is_pinned(&inode),
            // What the mount has ARMED, read from the one place that answers
            // it. No policy is armed in this build, so the refusal a policy
            // would cause appears the moment one is.
            inplace_update: !crate::stats::policy::ipu_disabled(
                crate::stats::policy::ipu_policy(self.options())),
        };
        plan::admit(&facts)?;

        // The cheap answer first: the cached extent describes one contiguous
        // run, and a run that already spans the range is proof there is
        // nothing to do — without reading a single node.
        let extent = if self.extent_is_sane(&inode) { inode.cached_extent() } else { None };
        if plan::extent_covers(extent, first, end) { return Ok(0); }

        let mut survey = Survey::new();
        for index in first..end {
            match self.mapped_addr(ino, index)? {
                Some(addr) => survey.note(addr),
                None => continue,
            }
        }
        if !survey.fragmented { return Ok(0); }

        // Enough log to hold the copy, or nothing is started. A rewrite that
        // stops half way leaves the range split across two places instead of
        // one, which is worse than the fragmentation it was called to fix.
        self.load_segments()?;
        let needed = survey.sections_needed(self.blks_per_sec());
        if !self.has_enough_free_secs(0, needed) { return Err(Errno::Eagain); }

        let mut moved = 0u64;
        for index in first..end {
            if self.relocate_block(ino, index)? { moved += 1; }
        }
        // The addresses all changed, so the cached run describes blocks the
        // file no longer has. Recomputing is the only repair: a patched
        // extent is one that is sometimes wrong, which reads as stale data.
        self.refresh_extent(ino)?;
        Ok(moved * blk)
    }

    /// The address block `index` of `ino` is stored at, or `None` when the
    /// file has nothing there.
    ///
    /// The compressed-cluster sentinel is nothing too: it is a marker in the
    /// address array rather than a block of the medium, and moving it would
    /// destroy the cluster it heads.
    /// # C: O(indirection depth) blocks
    pub(crate) fn mapped_addr(&self, ino: u32, index: u64) -> Result<Option<u32>, Errno> {
        let inode = self.read_inode(ino)?;
        let addr = self.stored_addr(&inode, ino, index)?;
        if crate::node::is_hole(addr) || crate::node::is_compressed(addr) { return Ok(None); }
        if !self.sb_main_contains(addr) { return Err(Errno::Euclean); }
        Ok(Some(addr))
    }

    /// Move one block of `ino` to the tail of its log, unchanged.
    ///
    /// The BYTES are copied verbatim rather than read through the file: an
    /// encrypted file's block is ciphertext on the medium, and decrypting it
    /// to write it back would put the file's contents on the medium in the
    /// clear. Reports whether a block was there to move.
    /// # C: O(BLKSIZE)
    fn relocate_block(&mut self, ino: u32, index: u64) -> Result<bool, Errno> {
        let Some(old) = self.mapped_addr(ino, index)? else { return Ok(false) };
        let inode = self.read_inode(ino)?;
        let (holder, ofs) = self.dnode_for_write(ino, index)?;
        // Read again through the holder the write will use: the survey and
        // the move are two walks, and acting on the first walk's address
        // after the second disagrees would repoint a slot at a stale block.
        let at = self.holder_addr(ino, holder, ofs)?;
        if at != old { return Ok(false); }
        let data = self.read_main_block(old)?;
        let dir = crate::mode::file_type(inode.mode) == vfs::FileType::Directory;
        let owner = match holder { Holder::Inode => ino, Holder::Direct(nid) => nid };
        let new = self.write_data(owner, ofs as u16, dir, old, &data)?;
        if new == NULL_ADDR { return Err(Errno::Eio); }
        self.set_holder_addr(ino, holder, ofs, new)?;
        Ok(true)
    }

}

#[cfg(test)]
#[path = "../tests/defrag/run.rs"]
mod tests;
