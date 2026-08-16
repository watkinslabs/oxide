//! The plain allocation: give the file the blocks of a range.
//!
//! What `fallocate` means with no operation bit set. The range gets real
//! blocks, so a later write into it cannot fail for want of space, and the
//! file's length grows to cover it unless `KEEP_SIZE` says otherwise.
//!
//! A PINNED file takes the other branch entirely. Its blocks have to be
//! contiguous and section-aligned, because something outside the filesystem is
//! going to address them directly, so the range is widened to whole sections
//! and taken out of a log reserved for the purpose — and a pinned file gets
//! blocks NO OTHER WAY, since an ordinary write to one only ever overwrites a
//! block it already has.
//!
//! A partial allocation is reported as the error it hit AND kept. The blocks
//! that landed have landed; reporting the whole call as failed would tell the
//! caller its file is unchanged when it is not, and the size is moved up to
//! the point reached so the file describes what it actually holds.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::*;
use crate::volume::dnode::put64;
use crate::volume::Volume;

use super::uapi::FALLOC_FL_KEEP_SIZE;

impl<S: SectorSource> Volume<S> {
    /// Give `ino` blocks for `[offset, offset + len)`.
    /// # C: O(blocks the range covers)
    pub(crate) fn expand_inode_data(&mut self, ino: u32, offset: u64, len: u64, mode: u32)
        -> Result<(), Errno> {
        let end = offset + len;
        self.newsize_ok(ino, end)?;
        let inode = self.read_inode(ino)?;
        if crate::pin::state::is_pinned(&inode) {
            return self.expand_pinned_range(ino, offset, len, mode);
        }
        self.convert_inline(ino)?;
        let blk = BLKSIZE as u64;
        let first = offset / blk;
        let last = end.div_ceil(blk);
        let mut reached = first;
        let mut stopped = None;
        for index in first..last {
            if let Err(e) = self.reserve_one_block(ino, index) { stopped = Some(e); break; }
            reached = index + 1;
        }
        if reached > first || stopped.is_none() {
            // The size describes what was actually allocated, which for a run
            // that stopped part way is the end of the last block that landed.
            let got = if reached == last { end } else { reached * blk };
            let keep = mode & FALLOC_FL_KEEP_SIZE != 0;
            let size = self.read_inode(ino)?.size;
            let blocks = self.count_blocks(ino)?;
            let size = if keep || got <= size { size } else { got };
            self.stamp_inode(ino, |b| {
                put64(b, I_SIZE, size);
                Self::set_iblocks(b, blocks);
            })?;
        }
        match stopped { Some(e) => Err(e), None => Ok(()) }
    }

    /// Give one index a block, leaving one it already had alone.
    ///
    /// A block already there is not replaced: the caller asked for the range to
    /// be backed, and rewriting a block that already backs it would move data
    /// for nothing and cost a fresh block out of the log per index.
    /// # C: O(BLKSIZE)
    fn reserve_one_block(&mut self, ino: u32, index: u64) -> Result<(), Errno> {
        if !crate::node::is_hole(self.index_addr(ino, index)?) { return Ok(()); }
        let zeroes = alloc::vec![0u8; BLKSIZE];
        self.write_one_block(ino, index, 0, &zeroes)
    }

    /// The pinned branch: whole sections, out of the pinned log.
    /// # C: O(blocks allocated)
    fn expand_pinned_range(&mut self, ino: u32, offset: u64, len: u64, mode: u32)
        -> Result<(), Errno> {
        let before = self.read_inode(ino)?.size;
        self.expand_pinned(ino, offset, len)?;
        // `expand_pinned` grows the size to cover the range, which is right for
        // its own callers and wrong for one that asked to keep it.
        if mode & FALLOC_FL_KEEP_SIZE != 0 {
            self.stamp_inode(ino, |b| put64(b, I_SIZE, before))?;
        }
        Ok(())
    }
}
