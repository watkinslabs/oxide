//! Taking a recovered block away from whoever holds it now.
//!
//! A block address recovered from the chain may already be live under a
//! DIFFERENT file. The generation that crashed had reassigned it, the
//! checkpoint being mounted still records the old owner, and pointing the
//! recovered file at it without touching the old owner leaves two files
//! sharing one block — each free to rewrite what the other reads, and each
//! entitled to release it.
//!
//! Who the old owner is comes from the summary block for the block's segment,
//! which records a node id and a slot for every block of the segment. That is
//! the only structure that maps an address BACK to its owner; a search of the
//! node table would have to read every node on the volume.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::*;
use crate::volume::curseg::{Curseg, Summary};
use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
    /// Whether the segment table says `addr` is live. # C: O(1)
    pub(crate) fn addr_is_live(&self, addr: u32) -> bool {
        let Some(segno) = self.sb.segno_of(addr) else { return false };
        let off = ((addr - self.sb.main_blkaddr) % self.sb.blks_per_seg()) as usize;
        self.segments().get(segno as usize).map(|e| e.is_valid(off)).unwrap_or(false)
    }

    /// The summary entry recording who owns `addr`.
    ///
    /// A segment one of the logs has open holds its summaries in memory, not
    /// on the medium: the block in the summary area is whatever the last
    /// checkpoint left, so reading it for an open segment names the previous
    /// occupant of the slot.
    /// # C: O(1 block)
    pub(crate) fn owner_of(&self, addr: u32) -> Result<Summary, Errno> {
        let segno = self.sb.segno_of(addr).ok_or(Errno::Eio)?;
        let slot = ((addr - self.sb.main_blkaddr) % self.sb.blks_per_seg()) as usize;
        if let Some(c) = self.curseg.iter().find(|c| c.segno == segno) {
            return Ok(c.summary(slot));
        }
        let block = self.read_block(sum_block_addr(self.sb.ssa_blkaddr, segno))?;
        let held = Curseg { segno, next_blkoff: 0, alloc_type: ALLOC_LFS, sum: block };
        Ok(held.summary(slot))
    }

    /// Drop whatever node still claims `addr`, unless it is `keep_nid` — the
    /// node the caller is about to rewrite in full, whose every slot the
    /// caller is already deciding.
    ///
    /// A summary entry naming a node that no longer holds the address is
    /// stale, not an error: out-of-place writes leave old summaries behind all
    /// the time, and the slot is only cleared when it still points here.
    /// # C: O(2 blocks)
    pub(crate) fn drop_previous_owner(&mut self, addr: u32, keep_nid: u32)
        -> Result<bool, Errno> {
        if !self.addr_is_live(addr) { return Ok(false); }
        let sum = self.owner_of(addr)?;
        let nid = sum.nid;
        if nid == 0 || nid == keep_nid { return Ok(false); }
        let Ok(node_addr) = self.node_addr(nid) else { return Ok(false) };
        if crate::node::is_hole(node_addr) { return Ok(false); }
        let Ok(node) = self.read_node(nid, None) else { return Ok(false) };
        let owner_ino = node.footer.ino;
        let slot = sum.ofs_in_node as usize;
        let (base, is_inode) = if node.footer.is_inode() {
            let inode = self.read_inode(owner_ino)?;
            if slot >= inode.addrs_per_inode() { return Ok(false); }
            (inode.addr_base(), true)
        } else {
            if slot >= DEF_ADDRS_PER_BLOCK { return Ok(false); }
            (0usize, false)
        };
        let at = base + slot * 4;
        let mut block = node.block;
        if le32(&block, at) != Some(addr) { return Ok(false); }
        block[at..at + 4].copy_from_slice(&NULL_ADDR.to_le_bytes());
        // Another address written outside the single-address funnel. Replay
        // runs before anything reads the volume, so nothing is cached yet on
        // the ordinary path — but the notification is what makes that a fact
        // about the ORDER rather than an assumption, and a replay that ever
        // ran later would otherwise leave a run describing a released block.
        let h = if is_inode { crate::volume::Holder::Inode }
                else { crate::volume::Holder::Direct(nid) };
        self.note_mapping_change(owner_ino, h, slot, NULL_ADDR)?;
        if is_inode {
            self.put_inode(owner_ino, block)?;
        } else {
            let inode = self.read_inode(owner_ino)?;
            let kind = self.node_kind(inode.mode);
            self.write_node(nid, owner_ino, block, kind)?;
        }
        // The cached extent describes the addresses just changed, so leaving
        // it would keep answering reads with the block that was taken away.
        self.refresh_extent(owner_ino)?;
        self.release_block(addr)?;
        Ok(true)
    }
}
