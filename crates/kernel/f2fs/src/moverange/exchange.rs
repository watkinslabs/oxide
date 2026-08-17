//! Repointing and copying the blocks themselves.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::{summary_off, BLKSIZE, BLKS_PER_SEG, NULL_ADDR};
use crate::volume::curseg::Summary;
use crate::volume::dnode::Holder;
use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
    /// Hand `blocks` blocks of `src` starting at `src_index` over to `dst`
    /// starting at `dst_index`.
    ///
    /// A hole in the source is left as a hole: the destination keeps whatever
    /// it had there, because a hole carries no data to hand over and clearing
    /// the destination's slot would destroy data the caller never named.
    /// # C: O(blocks) blocks
    pub(crate) fn exchange_blocks(&mut self, src: u32, dst: u32, src_index: u64,
                                  dst_index: u64, blocks: u64) -> Result<(), Errno> {
        self.load_segments()?;
        for i in 0..blocks {
            let from = src_index + i;
            let to = dst_index + i;
            let Some(addr) = self.mapped_addr(src, from)? else { continue };
            // The destination's own block goes first. It is being replaced,
            // and leaving it allocated while its slot is overwritten is the
            // leak the segment table cannot see.
            self.punch_block(dst, to)?;
            match self.open_log_slot(addr) {
                Some(slot) => self.repoint_block(src, dst, from, to, addr, slot)?,
                None => self.copy_block(src, dst, from, to, addr)?,
            }
        }
        Ok(())
    }

    /// Give `dst` the very block `src` holds, with nothing read or written.
    ///
    /// The source's slot is cleared BEFORE the destination's is set. Between
    /// the two the block belongs to nobody, which loses it if the volume dies
    /// there; the other order would leave two files owning one block, and the
    /// first of them to be shortened would hand a live block back to the
    /// allocator.
    /// # C: O(1) blocks
    fn repoint_block(&mut self, src: u32, dst: u32, from: u64, to: u64, addr: u32,
                     slot: (usize, usize)) -> Result<(), Errno> {
        // Repointing rewrites a summary entry, which a volume that never
        // overwrites anything in place will not do — even in an open log,
        // where the entry is only in memory.
        if self.options().mode == crate::opts::Mode::Lfs { return Err(Errno::Eopnotsupp); }
        let (src_holder, src_ofs) = self.dnode_for_write(src, from)?;
        self.set_holder_addr(src, src_holder, src_ofs, NULL_ADDR)?;
        let (dst_holder, dst_ofs) = match self.dnode_for_write(dst, to) {
            Ok(h) => h,
            Err(e) => {
                // Nothing owns the block at this instant. Putting it back is
                // the only outcome that neither loses it nor duplicates it.
                self.set_holder_addr(src, src_holder, src_ofs, addr)?;
                return Err(e);
            }
        };
        self.set_holder_addr(dst, dst_holder, dst_ofs, addr)?;
        // The cleaner reads the owner off the summary, not off the file. An
        // entry still naming the source would put the block back into the
        // source's slot at the next clean.
        let owner = match dst_holder { Holder::Inode => dst, Holder::Direct(nid) => nid };
        self.curseg[slot.0].set_summary(slot.1, Summary {
            nid: owner, version: 0, ofs_in_node: dst_ofs as u16,
        });
        // The block did not appear or disappear; it changed owner, so the
        // charge follows it. The source is relieved first, so a pair of files
        // with one owner between them never trips a limit on a move that
        // leaves that owner's total exactly where it was.
        self.uncharge_space(src, BLKSIZE as u64)?;
        self.charge_space(dst, BLKSIZE as u64)
    }

    /// Copy one block's bytes into a fresh block of `dst`, then punch the
    /// source's.
    ///
    /// The bytes go across verbatim. An encrypted file is refused before this
    /// point, so no block reaching here needs a key — and a block that did
    /// would have to be re-encrypted under the destination's, which is not a
    /// move.
    /// # C: O(BLKSIZE)
    fn copy_block(&mut self, src: u32, dst: u32, from: u64, to: u64, addr: u32)
        -> Result<(), Errno> {
        let data = self.read_main_block(addr)?;
        let inode = self.read_inode(dst)?;
        let dir = crate::mode::file_type(inode.mode) == vfs::FileType::Directory;
        let (holder, ofs) = self.dnode_for_write(dst, to)?;
        self.reserve_space(dst, BLKSIZE as u64)?;
        let new = match self.write_data(dst, match holder { Holder::Inode => dst,
                                                       Holder::Direct(nid) => nid },
                                        ofs as u16, dir, NULL_ADDR, &data) {
            Ok(new) => new,
            Err(e) => { self.release_reserved_space(dst, BLKSIZE as u64)?; return Err(e); }
        };
        self.claim_space(dst, BLKSIZE as u64)?;
        self.set_holder_addr(dst, holder, ofs, new)?;
        // Only now: until the destination holds a copy, the source's is the
        // only one there is.
        self.punch_block(src, from)
    }

    /// Free whatever `ino` holds at block `index`, leaving a hole.
    ///
    /// The slot is cleared before the block is released, so a volume that
    /// dies between the two leaves a block nothing points at rather than a
    /// pointer into space the allocator is free to hand out.
    /// # C: O(1) blocks
    pub(crate) fn punch_block(&mut self, ino: u32, index: u64) -> Result<(), Errno> {
        let inode = self.read_inode(ino)?;
        let addr = self.stored_addr(&inode, ino, index)?;
        if crate::node::is_hole(addr) { return Ok(()); }
        let (holder, ofs) = self.dnode_for_write(ino, index)?;
        self.set_holder_addr(ino, holder, ofs, NULL_ADDR)?;
        self.release_slot(ino, addr)
    }

    /// Where `addr`'s summary entry sits in an OPEN log, or `None` when its
    /// summary is already on the medium.
    ///
    /// The distinction decides whether the block may be repointed at all: an
    /// entry still in memory is retired by the next checkpoint along with
    /// everything else this mount has done, while one on the medium is part
    /// of the state a crash recovers to.
    /// # C: O(logs)
    fn open_log_slot(&self, addr: u32) -> Option<(usize, usize)> {
        let main = self.super_block().main_blkaddr;
        let off = addr.checked_sub(main)?;
        let segno = off / BLKS_PER_SEG;
        let slot = (off % BLKS_PER_SEG) as usize;
        let log = self.curseg.iter().position(|c| c.segno == segno)?;
        if summary_off(slot) + crate::uapi::SUMMARY_SIZE > BLKSIZE { return None; }
        Some((log, slot))
    }
}

#[cfg(test)]
#[path = "../tests/moverange/exchange.rs"]
mod tests;
