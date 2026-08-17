//! Making a span visible, undoing one that failed, and abandoning one.
//!
//! A commit MOVES blocks. The block the span wrote is already on the medium
//! and already correct for the file it is about to belong to, so the file's
//! index is pointed at it and the block the file used to have is released —
//! no copy, and no window in which the file's contents are half of each.
//!
//! A move that fails part way is put back. Each one records the address it
//! displaced, and the undo walk restores those: without it a failure leaves a
//! file made of some new blocks and some old ones, which is exactly the state
//! the whole mechanism exists to make impossible.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::*;
use crate::volume::dnode::put64;
use crate::volume::Volume;

/// One block moved, and what it displaced.
struct Moved {
    index: u64,
    old: u32,
    new: u32,
}

impl<S: SectorSource> Volume<S> {
    /// Make the span over `ino` visible and durable.
    ///
    /// Durability is part of the promise, not a separate call: a commit that
    /// returned before the file's nodes reached the medium would tell the
    /// caller its transaction had landed while a crash could still take it.
    /// # C: O(blocks in the span), plus a sync of the file
    pub fn commit_atomic_write(&mut self, ino: u32) -> Result<(), Errno> {
        self.writable_or_err()?;
        // Moving the span's blocks charges the file and gives the shadow's
        // charge back, both against the same owners.
        self.dquot_initialize(ino)?;
        // Every buffered write of this file has to be on the medium before
        // its addresses are read: a page not yet placed has no address, and
        // this operation is about to rearrange the ones that exist.
        self.flush_data_pages(ino)?;
        // A file with no span open is asked for its ordinary durability, which
        // is what a caller committing an empty transaction means.
        if !self.is_atomic_file(ino) { return self.fsync(ino).map(|_| ()); }
        let outcome = self.move_span(ino).and_then(|()| self.fsync(ino).map(|_| ()));
        // On failure the file goes back to the size it had; on success it
        // keeps the one the span gave it. What the COMMIT reported is what the
        // caller is told: a span that failed and then failed to tidy up is
        // still a span that failed, and reporting the tidying error instead
        // would hide why.
        let cleanup = self.finish_atomic_write(ino, outcome.is_err());
        outcome.and(cleanup)
    }

    /// Abandon the span over `ino`, leaving the file as it was.
    ///
    /// Succeeds when no span is open: the caller asked for a state the file is
    /// already in.
    /// # C: O(blocks the span wrote)
    pub fn abort_atomic_write(&mut self, ino: u32) -> Result<(), Errno> {
        if !self.is_atomic_file(ino) { return Ok(()); }
        self.dquot_initialize(ino)?;
        self.finish_atomic_write(ino, true)
    }

    /// Close a span: restore the size when asked, and reclaim the COW inode.
    ///
    /// The COW inode is released by dropping the hold the span had on it. It
    /// is an orphan, so the drop is what frees it and everything it still
    /// owns — after a commit that is nothing, and after an abort it is every
    /// block the span wrote.
    /// # C: O(blocks the COW inode still owns)
    pub(crate) fn finish_atomic_write(&mut self, ino: u32, clean: bool) -> Result<(), Errno> {
        let Some(a) = self.atomic.remove(&ino) else { return Ok(()) };
        if clean && self.writable {
            self.stamp_inode(ino, |b| put64(b, I_SIZE, a.original_size))?;
        }
        self.close_inode(a.cow_ino)
    }

    /// Point the file's index at every block the span wrote.
    /// # C: O(blocks in the span)
    fn move_span(&mut self, ino: u32) -> Result<(), Errno> {
        let a = self.atomic_entry(ino)?;
        let cow = a.cow_ino;
        let len = self.read_inode(ino)?.size.div_ceil(BLKSIZE as u64);
        let mut moved: Vec<Moved> = Vec::new();
        for index in 0..len {
            let cow_inode = self.read_inode(cow)?;
            let blk = self.stored_addr(&cow_inode, cow, index)?;
            if crate::node::is_hole(blk) { continue; }
            // A block the span wrote that is not a block of this volume is an
            // index that has been damaged, and moving it would point the file
            // at metadata.
            if !self.sb.valid_main_blkaddr(blk) {
                self.revoke(ino, cow, &moved)?;
                return Err(Errno::Euclean);
            }
            if let Err(e) = self.move_one(ino, cow, index, blk, &mut moved) {
                self.revoke(ino, cow, &moved)?;
                return Err(e);
            }
        }
        if a.replace { self.drop_unwritten(ino, &moved)?; }
        self.settle(ino, cow)?;
        if let Some(e) = self.atomic.get_mut(&ino) { e.committed = true; }
        Ok(())
    }

    /// Move one block across, recording what it displaced. # C: O(1 block)
    fn move_one(&mut self, ino: u32, cow: u32, index: u64, blk: u32, moved: &mut Vec<Moved>)
        -> Result<(), Errno> {
        // Charged BEFORE anything is destroyed: a span that runs the file out
        // of space part way through must leave the file's old block intact so
        // the undo has something to put back.
        self.charge_space(ino, BLKSIZE as u64)?;
        let (h, ofs) = self.dnode_for_write(ino, index)?;
        let old = self.holder_addr(ino, h, ofs)?;
        self.release_slot(ino, old)?;
        self.uncharge_space(cow, BLKSIZE as u64)?;
        self.set_holder_addr(ino, h, ofs, blk)?;
        // The COW inode's slot is CLEARED, not released: the block did not
        // die, it changed owner, and releasing it would free a block the file
        // now points at.
        let (ch, cofs) = self.dnode_for_write(cow, index)?;
        self.set_holder_addr(cow, ch, cofs, NULL_ADDR)?;
        moved.push(Moved { index, old, new: blk });
        Ok(())
    }

    /// Put every moved block back where it came from.
    ///
    /// The file gets its old address again and the span gets its block back,
    /// which leaves both exactly as they were before the commit began.
    /// # C: O(blocks moved)
    fn revoke(&mut self, ino: u32, cow: u32, moved: &[Moved]) -> Result<(), Errno> {
        for m in moved.iter().rev() {
            let (ch, cofs) = self.dnode_for_write(cow, m.index)?;
            self.set_holder_addr(cow, ch, cofs, m.new)?;
            self.charge_space(cow, BLKSIZE as u64)?;
            let (h, ofs) = self.dnode_for_write(ino, m.index)?;
            self.set_holder_addr(ino, h, ofs, m.old)?;
            if crate::node::is_hole(m.old) { self.uncharge_space(ino, BLKSIZE as u64)?; }
        }
        Ok(())
    }

    /// Discard everything a replacing span did not write.
    ///
    /// The file's old blocks were kept until now so an abort could put the
    /// file back; past the commit they are what the span replaced.
    /// # C: O(blocks discarded)
    fn drop_unwritten(&mut self, ino: u32, moved: &[Moved]) -> Result<(), Errno> {
        let mut next = 0u64;
        for m in moved {
            self.punch_range(ino, next, m.index)?;
            next = m.index + 1;
        }
        self.truncate_tail(ino, next)
    }

    /// Release the blocks of `[from, to)` without touching the file's size.
    /// # C: O(blocks released)
    fn punch_range(&mut self, ino: u32, from: u64, to: u64) -> Result<(), Errno> {
        for index in from..to {
            let inode = self.read_inode(ino)?;
            let addr = self.stored_addr(&inode, ino, index)?;
            if crate::node::is_hole(addr) { continue; }
            let (h, ofs) = self.dnode_for_write(ino, index)?;
            self.release_slot(ino, addr)?;
            self.set_holder_addr(ino, h, ofs, NULL_ADDR)?;
        }
        Ok(())
    }

    /// Bring both inodes' block counts and the file's cached extent back in
    /// line with what they now hold. # C: O(nodes both files have)
    fn settle(&mut self, ino: u32, cow: u32) -> Result<(), Errno> {
        let blocks = self.count_blocks(ino)?;
        self.stamp_inode(ino, |b| Self::set_iblocks(b, blocks))?;
        self.refresh_extent(ino)?;
        let cow_blocks = self.count_blocks(cow)?;
        self.stamp_inode(cow, |b| Self::set_iblocks(b, cow_blocks))?;
        Ok(())
    }
}
