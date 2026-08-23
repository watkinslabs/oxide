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

    /// Segments held back from the allocator so the cleaner always has
    /// somewhere to move live blocks to.
    ///
    /// What the volume was FORMATTED with, and nothing else. A volume that
    /// reserves none is refused at mount rather than given a floor here: a
    /// substituted one would report a reserve the volume does not have and
    /// leave the cleaner with nowhere to move live blocks the first time the
    /// volume filled.
    /// # C: O(1)
    pub(crate) fn gc_reserve(&self) -> u32 { self.cp.rsvd_segment_count }

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
    /// The held-back space comes off what is available here only for a caller
    /// the reserve is not FOR. `reserve_root=`/`reserve_node=` exist so that a
    /// full volume is still writable by the reserved uid, the reserved group
    /// and — where the call site honours it — a `CAP_SYS_RESOURCE` holder;
    /// subtracting from everyone reserves space nobody can reach. `ino` is the
    /// inode the allocation belongs to, `None` for a kernel-internal one,
    /// which reaches the reserve.
    ///
    /// `statfs` still subtracts unconditionally, and that is not the same
    /// question: it reports what an ORDINARY caller may use, which is the
    /// figure a tool sizing a write wants.
    /// # C: O(1)
    pub(crate) fn volume_has_room(&self, ino: Option<u32>, node: bool) -> Result<(), Errno> {
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::Block) {
            return Err(Errno::Enospc);
        }
        let r = self.reserve();
        let quota_file = ino.is_some_and(|i| self.is_quota_file(i));
        let caller = ino.and(vfs::reserved_caller(r.resgid));
        // The block half of a NODE allocation honours the capability only when
        // the node reserve is in force; the block-only path always does.
        let cap = !node || r.nodes != 0;
        let allow = crate::reserve::allow_reserved_root(&r, caller.as_ref(), quota_file, cap);
        let avail = crate::reserve::available_blocks(self.cp.user_block_count, &r, allow);
        if self.valid_block_count + 1 > avail { return Err(Errno::Enospc); }
        if node {
            let total = u64::from(self.max_nid()).saturating_sub(u64::from(RESERVED_NODE_NUM));
            // The node half always honours the capability, whatever the block
            // half above decided.
            let allow = crate::reserve::allow_reserved_root(&r, caller.as_ref(), quota_file, true);
            let ids = crate::reserve::available_nodes(total, &r, allow);
            if u64::from(self.valid_node_count) + 1 > ids { return Err(Errno::Enospc); }
        }
        Ok(())
    }

    /// The mount's held-back space and the identities it is held for. # C: O(1)
    pub(crate) fn reserve(&self) -> crate::reserve::Reserve {
        crate::reserve::Reserve {
            blocks: self.opts.reserve_root, nodes: self.opts.reserve_node,
            resuid: self.opts.resuid, resgid: self.opts.resgid,
        }
    }

    /// Take a block for something that did not occupy one before.
    ///
    /// A rewrite MOVES a block and needs no room; only a slot that held
    /// nothing is a claim on the volume's remaining space, so the count is
    /// consulted exactly where the occupancy grows.
    /// # C: O(main segments) worst case
    pub(crate) fn allocate_new_block(&mut self, ino: u32, kind: Kind, sum: Summary, old: u32,
                                     node: bool) -> Result<u32, Errno> {
        // A DATA slot holding a reservation already holds the room: it was
        // counted against the volume when the slot was set, and this
        // allocation is what takes it up. Demanding room for it again refuses,
        // at writeback, a write the caller was already told had landed — and
        // only on the full volume, where it matters most.
        //
        // A NODE reads the same value for a different reason: an id claimed
        // and not yet written reads as `NEW_ADDR` and has been charged
        // NOTHING, so it is the one case where the same value must still ask.
        let reserved = old == NEW_ADDR && !node;
        if crate::node::is_hole(old) && !reserved { self.volume_has_room(Some(ino), node)?; }
        self.allocate_block(kind, sum, old)
    }

    /// Give back a node the tree could not be made to reach.
    ///
    /// A node whose parent could not be changed is charged, counted and
    /// unreachable — nothing can ever find it to free it, and the space it
    /// holds never comes back. No BLOCK is stranded any more: the node was
    /// never placed, so what is undone is the id, the counts and the dirty
    /// page. The reference unwinds the same three things and no fourth.
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

    /// Change a node block: file it in the node mapping, DIRTY.
    ///
    /// Nothing reaches the medium here and no address is chosen. The node's
    /// identity goes into the footer, an inode's checksum is recomputed over
    /// the finished block, the id is made live in the node table with no
    /// address yet, and the bytes are left in the mapping. The segment, the
    /// log and the address are decided once, later, by `writeback_node` — the
    /// point of the whole arrangement, because a node changed four times
    /// between two checkpoints then costs ONE block instead of four, and every
    /// node a transaction touched lands in one run of the log.
    ///
    /// Two stamps deliberately do NOT happen here. The forward pointer names
    /// where the log goes next, which is not known until a block is taken; and
    /// the cold mark is stamped from `kind`, so the block's own footer is
    /// afterwards the only thing that says which log it belongs in.
    /// # C: O(BLKSIZE)
    pub(crate) fn write_node(&mut self, nid: u32, ino: u32, mut block: Vec<u8>, kind: Kind)
        -> Result<(), Errno> {
        self.writable_or_err()?;
        if block.len() != BLKSIZE { return Err(Errno::Einval); }
        let old = self.node_addr(nid).unwrap_or(NULL_ADDR);
        // `NEW_ADDR` no longer says on its own that the node is new: it is
        // also what a node changed and not yet placed reads as. The two are
        // told apart by the id's own state — an id handed out and not yet made
        // into a node is PREALLOCATED, and the very next line of this function
        // is what ends that. Treating a not-yet-placed node as new would
        // charge, count and re-announce the same node on its second change;
        // treating a preallocated id as old would leave every node created
        // since the last checkpoint uncharged and uncounted.
        let was_new = old == NULL_ADDR || self.nid_unwritten(nid);
        // A rewrite MOVES a block and costs nothing. A new INODE is charged as
        // an inode and not as space — the reference counts the inode itself,
        // never the block it occupies — while every other node costs its owner
        // one block. Charged HERE rather than at writeback, because this is
        // where the caller can still be told no: a node the caller was told it
        // had, refused later for space, has nowhere to go back to.
        let owed = was_new && nid != ino;
        if owed { self.reserve_space(ino, BLKSIZE as u64)?; }
        if was_new {
            if let Err(e) = self.volume_has_room(Some(ino), true) {
                if owed { self.release_reserved_space(ino, BLKSIZE as u64)?; }
                return Err(e);
            }
        }
        let f = NODE_FOOTER_OFF;
        block[f + FOOTER_NID..f + FOOTER_NID + 4].copy_from_slice(&nid.to_le_bytes());
        block[f + FOOTER_INO..f + FOOTER_INO + 4].copy_from_slice(&ino.to_le_bytes());
        // The cold mark is what tells a dnode of a file from a dnode of a
        // directory once the caller is gone, and the offset already in the
        // footer tells either from an indirection node. Together they are what
        // the log is read off at writeback, which is where the reference reads
        // it from too — so the mark is stamped from `kind` and the other three
        // bits of the flag word, which carry the recovery marks, are left be.
        curseg::stamp_node_temp(&mut block, kind);
        if nid == ino { self.seal_inode(&mut block); }
        if was_new {
            self.nat_cache_forget(nid);
            self.nat_dirty.insert(nid, NatEntry { version: 0, ino, block_addr: NEW_ADDR });
            // The id is a live node now, so the cache stops holding it: an id
            // left recorded as handed out is one the failure path could give
            // back while a node is using it.
            self.free_nids.alloc_done(nid);
            self.valid_node_count += 1;
            // The block this node will occupy is counted against the volume
            // from now, not from writeback. A window in which a promised node
            // is uncounted is a window in which the volume says it has room it
            // has already given away.
            self.charge_reservation();
            if owed { self.claim_space(ino, BLKSIZE as u64)?; }
        }
        self.node_cache.store(nid, block)?;
        self.dirty = true;
        Ok(())
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
    pub(crate) fn write_data(&mut self, ino: u32, owner: u32, ofs: u16, dir: bool, old: u32,
                             data: &[u8]) -> Result<u32, Errno> {
        self.write_data_flags(ino, owner, ofs, dir, old, data, block::RequestFlags::NONE)
    }

    /// The same, with what the file this page belongs to has been told about
    /// how urgent its writes are. # C: O(BLKSIZE)
    pub(crate) fn write_data_flags(&mut self, ino: u32, owner: u32, ofs: u16, dir: bool, old: u32,
                                   data: &[u8], flags: block::RequestFlags) -> Result<u32, Errno> {
        let kind = if dir { Kind::DirData } else { Kind::FileData };
        self.write_data_kind_flags(ino, kind, owner, ofs, old, data, flags)
    }

    /// The same, into a named log.
    ///
    /// A pinned file's blocks must come out of the pinned log rather than the
    /// one its temperature would pick, so the log is a parameter wherever the
    /// caller knows something the block's contents do not say.
    /// # C: O(BLKSIZE)
    pub(crate) fn write_data_kind(&mut self, ino: u32, kind: Kind, owner: u32, ofs: u16, old: u32,
                                  data: &[u8]) -> Result<u32, Errno> {
        self.write_data_kind_flags(ino, kind, owner, ofs, old, data, block::RequestFlags::NONE)
    }

    /// The same, carrying the hints this page's file was given. # C: O(BLKSIZE)
    pub(crate) fn write_data_kind_flags(&mut self, ino: u32, kind: Kind, owner: u32, ofs: u16,
                                        old: u32, data: &[u8], flags: block::RequestFlags)
        -> Result<u32, Errno> {
        self.write_data_crypt(ino, kind, owner, ofs, old, data, flags, None)
    }

    /// The same, for a page whose contents the layer beneath must encrypt.
    ///
    /// The address this allocates is not part of the encryption: a data unit
    /// number comes from the file and its offset, never from where the block
    /// happened to land, which is what lets an out-of-place write move a block
    /// without changing a byte of its ciphertext.
    /// # C: O(BLKSIZE)
    pub(crate) fn write_data_crypt(&mut self, ino: u32, kind: Kind, owner: u32, ofs: u16, old: u32,
                                   data: &[u8], flags: block::RequestFlags,
                                   ctx: Option<&block::crypto::Ctx>) -> Result<u32, Errno> {
        self.writable_or_err()?;
        // A page of data dropped on the way to the medium, while a checkpoint
        // is being re-enabled — the one window the reference arms this in.
        if self.sbi.is_set(crate::sbflags::bits::ENABLE_CHECKPOINT)
            && crate::fault::time_to_inject(&self.fault, crate::fault::Fault::SkipWrite) {
            return Err(Errno::Einval);
        }
        let sum = Summary { nid: owner, version: 0, ofs_in_node: ofs };
        let addr = self.allocate_new_block(ino, kind, sum, old, false)?;
        let mut block = vec![0u8; BLKSIZE];
        let take = data.len().min(BLKSIZE);
        block[..take].copy_from_slice(&data[..take]);
        self.write_block_crypt(addr, &block, flags, ctx)?;
        // Whose block it was is known HERE and nowhere below: the block writer
        // sees an address, and an address cannot say which file's `fsync` will
        // have to fence the member it landed on.
        self.note_file_write(ino, addr);
        {
            use crate::stats::iostat::Io;
            self.io_account(self.io_gc_kind(Io::FsData, Io::FsGcData), BLKSIZE as u64, false);
        }
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
    /// the segment update to clear — but it was counted against the VOLUME and
    /// charged to the OWNER when it was made, and both come back here.
    /// Releasing it as if it were a block would lower a count nothing raised;
    /// releasing only the volume's half would leave the owner charged forever
    /// for a block that was never written.
    /// # C: O(1)
    pub(crate) fn release_slot(&mut self, ino: u32, addr: u32) -> Result<(), Errno> {
        // The slot has already been cleared by the caller. Leaving the block
        // behind is what makes this a block the segment table calls live and
        // no file names — the inconsistency this site exists to produce.
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::BlkaddrConsistence) {
            return Ok(());
        }
        if addr == NEW_ADDR {
            self.release_reservation();
            return self.uncharge_space(ino, BLKSIZE as u64);
        }
        if crate::node::is_hole(addr) { return Ok(()); }
        self.release_block(addr)?;
        self.uncharge_space(ino, BLKSIZE as u64)
    }

    /// Release a whole node: its block, and its table entry. # C: O(1)
    pub(crate) fn release_node(&mut self, nid: u32) -> Result<(), Errno> {
        if nid == 0 { return Ok(()); }
        // The id can be handed out again, so a page left behind would answer
        // for whatever node next takes it. Dropped before the table entry, so
        // no window exists in which the id is free and the mapping still
        // speaks for it.
        self.forget_node_page(nid);
        // An id handed out and never made into a node was charged nothing and
        // counted nowhere, so nothing comes back for it.
        let claimed = self.nid_unwritten(nid);
        let live = match self.node_addr(nid) {
            Ok(addr) => {
                self.release_block(addr)?;
                // A node changed but not yet placed occupies no block, so
                // there is no bit to clear — but it was counted against the
                // volume when it was changed, and that count comes back here.
                if addr == NEW_ADDR && !claimed { self.release_reservation(); }
                addr != NULL_ADDR && !claimed
            }
            Err(_) => false,
        };
        self.nat_cache_forget(nid);
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
