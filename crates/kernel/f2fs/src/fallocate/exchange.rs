//! Moving a run of blocks from one index of a file to another.
//!
//! The half `COLLAPSE_RANGE` and `INSERT_RANGE` share, and the only part of
//! either that can lose data. Every block after the point moves to a different
//! index, and the two things that record where a block belongs — the node slot
//! that names its address and the summary entry that names its owner and slot
//! — must agree afterwards. A block whose address moved and whose summary did
//! not reads as dead to the cleaner, which then hands its space to somebody
//! else while the file still points at it.
//!
//! So the block is COPIED to a fresh address written with the new slot, and the
//! old one released. That is the reference's own second path for this — the one
//! it takes whenever the address cannot simply be re-pointed — and it keeps the
//! two records in step by construction rather than by remembering to update
//! both.
//!
//! Direction matters and is the caller's to get right. Moving a run DOWN walks
//! forwards, so a slot is vacated before it is filled; moving UP walks
//! backwards, for the same reason. A walk in the wrong direction overwrites a
//! block it has not moved yet.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::*;
use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
    /// Move block `from` of `ino` to index `to`, leaving `from` a hole.
    ///
    /// A `from` that is already a hole leaves `to` a hole too: the destination
    /// is cleared rather than left alone, because a run being moved over an
    /// older one must not leave the older one's blocks showing through the
    /// gaps.
    /// # C: O(BLKSIZE)
    pub(crate) fn move_block(&mut self, ino: u32, from: u64, to: u64) -> Result<(), Errno> {
        let old = self.index_addr(ino, from)?;
        if crate::node::is_hole(old) {
            // Nothing to move, and the destination must not keep what it had.
            if let Some((holder, ofs)) = self.dnode_for_read(ino, to)? {
                let had = self.holder_addr(ino, holder, ofs)?;
                if had != NULL_ADDR {
                    self.set_holder_addr(ino, holder, ofs, NULL_ADDR)?;
                    self.release_slot(ino, had)?;
                }
            }
            return Ok(());
        }
        let page = self.read_main_block(old)?;
        // Written through the ordinary one-block path rather than by hand, so
        // the reservation, the quota charge and the destination's own old
        // block are settled by the code that already owns those rules. A
        // second implementation of them here is a second place for them to be
        // wrong, and the way they go wrong is a count that drifts silently.
        self.write_one_block(ino, to, 0, &page)?;
        // Cleared first, released second: a crash between them leaves a block
        // nothing names, never a name pointing at a freed block.
        let (src_holder, src_ofs) = match self.dnode_for_read(ino, from)? {
            Some(h) => h,
            None => return Ok(()),
        };
        self.set_holder_addr(ino, src_holder, src_ofs, NULL_ADDR)?;
        self.release_slot(ino, old)
    }

    /// Move `count` blocks of `ino` starting at `from` down to `to`.
    ///
    /// Forwards, because `to` is below `from`: each destination is vacated by
    /// the step before it reaches it.
    /// # C: O(count) blocks
    pub(crate) fn move_run_down(&mut self, ino: u32, from: u64, to: u64, count: u64)
        -> Result<(), Errno> {
        for i in 0..count { self.move_block(ino, from + i, to + i)?; }
        Ok(())
    }

    /// Move `count` blocks of `ino` starting at `from` up to `to`.
    ///
    /// Backwards, because `to` is above `from`: walking forwards would write
    /// the first block over one the walk has not moved yet.
    /// # C: O(count) blocks
    pub(crate) fn move_run_up(&mut self, ino: u32, from: u64, to: u64, count: u64)
        -> Result<(), Errno> {
        for i in (0..count).rev() { self.move_block(ino, from + i, to + i)?; }
        Ok(())
    }
}
