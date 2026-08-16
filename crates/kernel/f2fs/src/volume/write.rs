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
        if !self.curseg[log].has_room() { self.open_segment(log)?; }
        if !self.curseg[log].has_room() { return Err(Errno::Enospc); }
        let slot = self.curseg[log].next_blkoff as usize;
        let addr = self.curseg[log].next_addr(self.sb.main_blkaddr);
        self.curseg[log].set_summary(slot, sum);
        self.advance(log);
        self.update_seg(addr, true)?;
        self.update_seg(old, false)?;
        self.note_discard(old);
        if !self.curseg[log].has_room() { self.open_segment(log)?; }
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
        let old = self.curseg[log].segno;
        if old != NULL_SEGNO {
            let node = log >= NR_CURSEG_DATA_TYPE;
            self.curseg[log].seal(node);
            let at = sum_block_addr(self.sb.ssa_blkaddr, old);
            let block = self.curseg[log].sum.clone();
            self.write_block(at, &block)?;
        }
        let hint = if old == NULL_SEGNO { 0 } else { old };
        // Recycling is asked for by the mount and only possible when a
        // partly-used segment exists; otherwise a fresh one is opened, which
        // is what an append-only volume always does.
        if curseg::wants_recycle(self.opts.alloc_mode) {
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
        let sum = Summary { nid, version: 0, ofs_in_node: 0 };
        let addr = self.allocate_block(kind, sum, old)?;
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
        self.write_block(addr, &block)?;
        // A node id claimed but not yet written reads as `NEW_ADDR`; counting
        // only the null case would leave every freshly created node
        // uncounted, and the checkpoint would under-report the volume.
        let was_new = crate::node::is_hole(old);
        self.nat_dirty.insert(nid, NatEntry { version: 0, ino, block_addr: addr });
        if was_new {
            self.valid_node_count += 1;
            // A rewrite MOVES a block and costs nothing. A new INODE is
            // charged as an inode and not as space — the reference counts the
            // inode itself, never the block it occupies — while every other
            // node reserves one block against the owner.
            if nid != ino { self.charge_space(ino, BLKSIZE as u64)?; }
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
        self.writable_or_err()?;
        let kind = if dir { Kind::DirData } else { Kind::FileData };
        let sum = Summary { nid: owner, version: 0, ofs_in_node: ofs };
        let addr = self.allocate_block(kind, sum, old)?;
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
        Ok(())
    }

    /// A node id nothing is using.
    ///
    /// The search consults the dirty set, the journal and the table in that
    /// order, so an id handed out earlier in this mount is never handed out
    /// twice — which would make one node overwrite another.
    /// # C: O(scanned ids)
    pub(crate) fn alloc_nid(&mut self) -> Result<u32, Errno> {
        let max = self.max_nid();
        let start = self.next_free_nid.max(RESERVED_NODE_NUM);
        for nid in start..max {
            if self.nid_is_free(nid)? {
                self.next_free_nid = nid + 1;
                // Claim it immediately: an id that is free but unrecorded
                // would be handed out again by the very next call.
                self.nat_dirty
                    .insert(nid, NatEntry { version: 0, ino: nid, block_addr: NEW_ADDR });
                return Ok(nid);
            }
        }
        Err(Errno::Enospc)
    }

    /// Whether `nid` currently names nothing. # C: O(1 block)
    fn nid_is_free(&self, nid: u32) -> Result<bool, Errno> {
        if let Some(e) = self.nat_dirty.get(&nid) { return Ok(e.block_addr == NULL_ADDR); }
        if let Some(e) = crate::nat::journalled(&self.nat_journal, nid) {
            return Ok(e.block_addr == NULL_ADDR);
        }
        let addr = crate::nat::block_addr(
            self.sb.nat_blkaddr,
            self.sb.blks_per_seg(),
            nid,
            &self.nat_bitmap,
        );
        let block = self.read_block(addr)?;
        let (_, off) = crate::nat::locate(nid);
        let e = crate::summary::nat_entry(&block, off).ok_or(Errno::Eio)?;
        Ok(e.block_addr == NULL_ADDR)
    }
}

#[cfg(test)]
#[path = "../tests/gcwire.rs"]
mod tests;
