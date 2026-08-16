//! Allocating a block and putting a node or a page of data in it.
//!
//! Every write is OUT OF PLACE. A block is never rewritten where it sits: a
//! fresh block is taken from the tail of the appropriate log, the new contents
//! go there, and the old block is released. That is what makes the volume
//! recoverable — the previous checkpoint's blocks are all still intact until
//! the next checkpoint retires them — and it is why a single byte changed in a
//! file rewrites the direct node and the inode above it too.
//!
//! The node table update is in MEMORY. A node's new address is recorded in the
//! dirty set and reaches the medium only at the next checkpoint, so every read
//! inside this mount must consult that set before the journal and the table.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::summary::NatEntry;
use crate::uapi::*;

use super::curseg::{self, Kind, Summary};
use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Refuse before touching anything if this mount may not write. # C: O(1)
    pub(crate) fn writable_or_err(&self) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        Ok(())
    }

    /// Put `data` at `addr`. # C: O(BLKSIZE)
    pub(crate) fn write_block(&self, addr: u32, data: &[u8]) -> Result<(), Errno> {
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::WriteIo) {
            return Err(Errno::Eio);
        }
        if data.len() != BLKSIZE { return Err(Errno::Einval); }
        if !self.sb.valid_main_blkaddr(addr) && u64::from(addr) >= self.sb.max_blkaddr() {
            return Err(Errno::Eio);
        }
        self.source.write_sectors(u64::from(addr), data)
    }

    /// Segments held back from the allocator so the cleaner always has
    /// somewhere to move live blocks to.
    ///
    /// The checkpoint records what the volume was formatted with; the floor of
    /// one is this build's own, because a cleaner with no destination is a
    /// cleaner that cannot run at the only moment it is wanted.
    /// # C: O(1)
    pub(crate) fn gc_reserve(&self) -> u32 { self.cp.rsvd_segment_count.max(1) }

    /// Whether the volume has room for one more block, and for one more node
    /// when the block is a node's.
    ///
    /// Both counts are VOLUME-wide, and both a new node and a new page of data
    /// come out of the same one. A log that still has room inside its own open
    /// segment must not be able to keep growing metadata on a volume with no
    /// space left: the node logs and the data logs drain independently, so
    /// without a shared count a full volume answers `ENOSPC` to every write
    /// while still handing out node blocks.
    ///
    /// The root reserve comes off what is available here for the same reason
    /// `statfs` reports it: it is space an ordinary allocation may not have.
    /// # C: O(1)
    pub(crate) fn volume_has_room(&self, node: bool) -> Result<(), Errno> {
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::Block) {
            return Err(Errno::Enospc);
        }
        let avail = self.cp.user_block_count.saturating_sub(u64::from(self.opts.reserve_root));
        if self.valid_block_count + 1 > avail { return Err(Errno::Enospc); }
        if node {
            let ids = u64::from(self.max_nid()).saturating_sub(u64::from(RESERVED_NODE_NUM));
            if u64::from(self.valid_node_count) + 1 > ids { return Err(Errno::Enospc); }
        }
        Ok(())
    }

    /// Take a block for something that did not occupy one before.
    ///
    /// A rewrite MOVES a block and needs no room; only a slot that held
    /// nothing is a claim on the volume's remaining space, so the count is
    /// consulted exactly where the occupancy grows.
    /// # C: O(main segments) worst case
    pub(crate) fn allocate_new_block(&mut self, kind: Kind, sum: Summary, old: u32, node: bool)
        -> Result<u32, Errno> {
        if crate::node::is_hole(old) { self.volume_has_room(node)?; }
        self.allocate_block(kind, sum, old)
    }

    /// Give back a node the tree could not be made to reach.
    ///
    /// A node whose parent could not be rewritten is allocated, charged,
    /// counted and unreachable — nothing can ever find it to free it, and the
    /// space it holds never comes back. The reference cannot reach that state
    /// because its parent link is a memory update that does not fail; here the
    /// link is another out-of-place write, so the node is undone the moment
    /// the link does not land.
    /// # C: O(1)
    pub(crate) fn undo_new_node(&mut self, ino: u32, nid: u32) -> Result<(), Errno> {
        self.release_node(nid)?;
        self.uncharge_space(ino, BLKSIZE as u64)
    }

    /// Take the next block of the log `kind` belongs to, releasing `old`.
    ///
    /// The summary entry goes down BEFORE the log advances: it names the owner
    /// of the block just handed out, and writing it after the advance would
    /// label the next block instead.
    /// # C: O(main segments) worst case, when a log must open a segment
    pub(crate) fn allocate_block(&mut self, kind: Kind, sum: Summary, old: u32)
        -> Result<u32, Errno> {
        self.load_segments()?;
        let log = curseg::log_for(kind, self.opts.active_logs);
        if !self.curseg_has_room(log) { self.open_segment(log)?; }
        if !self.curseg_has_room(log) { return Err(Errno::Enospc); }
        let slot = self.curseg[log].next_blkoff as usize;
        let addr = self.curseg[log].next_addr(self.sb.main_blkaddr);
        self.curseg[log].set_summary(slot, sum);
        self.advance(log);
        self.update_seg(addr, true)?;
        self.update_seg(old, false)?;
        self.note_discard(old);
        if !self.curseg_has_room(log) { self.open_segment(log)?; }
        self.dirty = true;
        Ok(addr)
    }

    /// Move a log past the block it just handed out.
    ///
    /// Appending steps by one; recycling steps to the next block nothing is
    /// using, which is why the segment table has to be updated before the
    /// step rather than after.
    /// # C: O(blocks per segment) when recycling
    fn advance(&mut self, log: usize) {
        let seg = self.curseg[log].segno;
        let next = self.curseg[log].next_blkoff + 1;
        self.curseg[log].next_blkoff = if self.curseg[log].alloc_type == ALLOC_SSR {
            self.next_free_block(seg, next).unwrap_or(self.sb.blks_per_seg() as u16)
        } else {
            next
        };
    }

    /// Close a log's segment and open another.
    ///
    /// The closing segment's summary block goes to the summary area first.
    /// That block is the only record of which node owns each block of the
    /// segment; a segment closed without it cannot be cleaned, and the space
    /// is lost for the life of the filesystem.
    /// # C: O(main segments)
    pub(crate) fn open_segment(&mut self, log: usize) -> Result<(), Errno> {
        self.load_segments()?;
        // The pinned log opens a whole SECTION, never a recycled segment: a
        // pinned block may not be moved, so it may not share a section with
        // blocks the cleaner is free to relocate.
        if log == crate::uapi::CURSEG_COLD_DATA_PINNED { return self.open_pinned_section(); }
        let old = self.curseg[log].segno;
        if old != NULL_SEGNO {
            let node = log >= NR_CURSEG_DATA_TYPE;
            self.curseg[log].seal(node);
            let at = sum_block_addr(self.sb.ssa_blkaddr, old);
            let block = self.curseg[log].sum.clone();
            self.write_block(at, &block)?;
        }
        // A segment the log is leaving empty is not free: the checkpoint on
        // the medium still names what was in it. Held here rather than at the
        // release that emptied it, because until now a log was appending to
        // it and it was nobody else's to take.
        self.retire_segment(old);
        let hint = if old == NULL_SEGNO { 0 } else { old };
        // Recycling is asked for by the mount and only possible when a
        // partly-used segment exists; otherwise a fresh one is opened, which
        // is what an append-only volume always does. The age-threshold log
        // ALWAYS recycles, whatever the mount asked for: it exists to put old
        // blocks beside other old blocks, and a fresh empty segment is the one
        // place with nothing to put them beside.
        if curseg::wants_recycle(self.opts.alloc_mode) || log == CURSEG_ALL_DATA_ATGC {
            if let Some((segno, off)) = self.find_victim_seg(hint) {
                let at = sum_block_addr(self.sb.ssa_blkaddr, segno);
                let sum = self.read_block(at).unwrap_or_else(|_| vec![0u8; BLKSIZE]);
                self.curseg[log].segno = segno;
                self.curseg[log].next_blkoff = off;
                self.curseg[log].alloc_type = ALLOC_SSR;
                self.curseg[log].sum = sum;
                return Ok(());
            }
        }
        // Clean BEFORE the last segment goes, not after. The cleaner moves
        // live blocks out of a victim, which needs somewhere to put them, so a
        // volume with nothing free cannot clean at all — waiting until then
        // strands the space permanently. A failure to clean is not reported
        // here: it is only a failure if the allocation itself then fails.
        let reserve = self.gc_reserve();
        if !self.recovering && self.free_segment_count() <= reserve {
            let _ = self.collect(reserve + 1);
        }
        let segno = self.find_free_seg(hint).ok_or(Errno::Enospc)?;
        self.curseg[log].segno = segno;
        self.curseg[log].next_blkoff = 0;
        self.curseg[log].alloc_type = ALLOC_LFS;
        self.curseg[log].sum = vec![0u8; BLKSIZE];
        Ok(())
    }

    /// Write a node block out of place and record its new address.
    ///
    /// The footer's own forward pointer is stamped with the address the block
    /// is going to, and an inode's checksum is recomputed last, over the
    /// finished block — both are inside what the checksum covers.
    /// # C: O(BLKSIZE)
    pub(crate) fn write_node(&mut self, nid: u32, ino: u32, mut block: Vec<u8>, kind: Kind)
        -> Result<u32, Errno> {
        self.writable_or_err()?;
        if block.len() != BLKSIZE { return Err(Errno::Einval); }
        let old = self.node_addr(nid).unwrap_or(NULL_ADDR);
        // A node id claimed but not yet written reads as `NEW_ADDR`; counting
        // only the null case would leave every freshly created node
        // uncounted, and the checkpoint would under-report the volume.
        let was_new = crate::node::is_hole(old);
        // A rewrite MOVES a block and costs nothing. A new INODE is charged as
        // an inode and not as space — the reference counts the inode itself,
        // never the block it occupies — while every other node costs its owner
        // one block. That block is PROMISED here and taken up once the log has
        // handed one out: a log with no room gives the promise back rather
        // than leaving the owner charged for a node that does not exist.
        let owed = was_new && nid != ino;
        if owed { self.reserve_space(ino, BLKSIZE as u64)?; }
        let sum = Summary { nid, version: 0, ofs_in_node: 0 };
        let addr = match self.allocate_new_block(kind, sum, old, true) {
            Ok(addr) => addr,
            Err(e) => {
                if owed { self.release_reserved_space(ino, BLKSIZE as u64)?; }
                return Err(e);
            }
        };
        let f = NODE_FOOTER_OFF;
        block[f + FOOTER_NID..f + FOOTER_NID + 4].copy_from_slice(&nid.to_le_bytes());
        block[f + FOOTER_INO..f + FOOTER_INO + 4].copy_from_slice(&ino.to_le_bytes());
        block[f + FOOTER_CP_VER..f + FOOTER_CP_VER + 8]
            .copy_from_slice(&self.cp.version.to_le_bytes());
        // The chain a crash is recovered from is built here: each node names
        // the block the log will hand out NEXT, so a walk forward from the
        // checkpoint's position reaches everything written after it. Stamping
        // the block's own address instead makes every chain one link long and
        // no crash tail recoverable. Read after `allocate_block`, which has
        // already advanced the log and opened a fresh segment if this write
        // filled one.
        let next = self.curseg[curseg::log_for(kind, self.opts.active_logs)]
            .next_addr(self.sb.main_blkaddr);
        block[f + FOOTER_NEXT_BLKADDR..f + FOOTER_NEXT_BLKADDR + 4]
            .copy_from_slice(&next.to_le_bytes());
        if nid == ino { self.seal_inode(&mut block); }
        if let Err(e) = self.write_block(addr, &block) {
            if owed { self.release_reserved_space(ino, BLKSIZE as u64)?; }
            return Err(e);
        }
        self.nat_dirty.insert(nid, NatEntry { version: 0, ino, block_addr: addr });
        if was_new {
            // The id is a live node now, so the cache stops holding it: an id
            // left recorded as handed out is one the failure path could give
            // back while a node is using it.
            self.free_nids.alloc_done(nid);
            self.valid_node_count += 1;
            if owed { self.claim_space(ino, BLKSIZE as u64)?; }
        }
        Ok(addr)
    }

    /// Recompute an inode block's checksum, if the volume keeps them.
    /// # C: O(BLKSIZE)
    pub(crate) fn seal_inode(&self, block: &mut [u8]) {
        if !crate::features::has_inode_chksum(self.sb.feature) { return; }
        if block[I_INLINE] & crate::flags::EXTRA_ATTR == 0 { return; }
        let extra = le16(block, I_EXTRA_ISIZE).unwrap_or(0) as usize;
        if I_INODE_CHECKSUM + 4 > OFFSET_OF_END_OF_I_EXT + extra { return; }
        block[I_INODE_CHECKSUM..I_INODE_CHECKSUM + 4].fill(0);
        if let Some(c) = crate::checksum::inode_chksum(self.inode_seed, block) {
            block[I_INODE_CHECKSUM..I_INODE_CHECKSUM + 4].copy_from_slice(&c.to_le_bytes());
        }
    }

    /// Write one page of a file's data out of place, releasing `old`.
    /// # C: O(BLKSIZE)
    pub(crate) fn write_data(&mut self, owner: u32, ofs: u16, dir: bool, old: u32, data: &[u8])
        -> Result<u32, Errno> {
        let kind = if dir { Kind::DirData } else { Kind::FileData };
        self.write_data_kind(kind, owner, ofs, old, data)
    }

    /// The same, into a named log.
    ///
    /// A pinned file's blocks must come out of the pinned log rather than the
    /// one its temperature would pick, so the log is a parameter wherever the
    /// caller knows something the block's contents do not say.
    /// # C: O(BLKSIZE)
    pub(crate) fn write_data_kind(&mut self, kind: Kind, owner: u32, ofs: u16, old: u32,
                                  data: &[u8]) -> Result<u32, Errno> {
        self.writable_or_err()?;
        // A page of data dropped on the way to the medium, while a checkpoint
        // is being re-enabled — the one window the reference arms this in.
        if self.sbi.is_set(crate::sbflags::bits::ENABLE_CHECKPOINT)
            && crate::fault::time_to_inject(&self.fault, crate::fault::Fault::SkipWrite) {
            return Err(Errno::Einval);
        }
        let sum = Summary { nid: owner, version: 0, ofs_in_node: ofs };
        let addr = self.allocate_new_block(kind, sum, old, false)?;
        let mut block = vec![0u8; BLKSIZE];
        let take = data.len().min(BLKSIZE);
        block[..take].copy_from_slice(&data[..take]);
        self.write_block(addr, &block)?;
        Ok(addr)
    }

    /// Release a block that is no longer part of any file. # C: O(1)
    pub(crate) fn release_block(&mut self, addr: u32) -> Result<(), Errno> {
        if crate::node::is_hole(addr) { return Ok(()); }
        self.load_segments()?;
        self.update_seg(addr, false)?;
        self.note_discard(addr);
        self.dirty = true;
        Ok(())
    }

    /// Release whatever a file's slot held, block or reservation.
    ///
    /// A reservation occupies no block of the medium, so there is no bit for
    /// the segment update to clear and no space charged to the owner — but it
    /// was counted against the VOLUME when it was made, and that is what comes
    /// back here. Releasing it as if it were a block would lower a count
    /// nothing raised and hand the owner space it never spent.
    /// # C: O(1)
    pub(crate) fn release_slot(&mut self, ino: u32, addr: u32) -> Result<(), Errno> {
        // The slot has already been cleared by the caller. Leaving the block
        // behind is what makes this a block the segment table calls live and
        // no file names — the inconsistency this site exists to produce.
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::BlkaddrConsistence) {
            return Ok(());
        }
        if addr == NEW_ADDR { self.release_reservation(); return Ok(()); }
        if crate::node::is_hole(addr) { return Ok(()); }
        self.release_block(addr)?;
        self.uncharge_space(ino, BLKSIZE as u64)
    }

    /// Release a whole node: its block, and its table entry. # C: O(1)
    pub(crate) fn release_node(&mut self, nid: u32) -> Result<(), Errno> {
        if nid == 0 { return Ok(()); }
        let live = match self.node_addr(nid) {
            Ok(addr) => { self.release_block(addr)?; !crate::node::is_hole(addr) }
            Err(_) => false,
        };
        self.nat_dirty.insert(nid, NatEntry { version: 0, ino: 0, block_addr: NULL_ADDR });
        if live { self.valid_node_count = self.valid_node_count.saturating_sub(1); }
        if nid < self.next_free_nid { self.next_free_nid = nid; }
        self.return_nid(nid);
        Ok(())
    }

}

#[cfg(test)]
#[path = "../tests/gcwire.rs"]
mod tests;
