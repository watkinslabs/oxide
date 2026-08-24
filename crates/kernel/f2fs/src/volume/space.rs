//! What `statfs` reports.
//!
//! The counts come from the mount's live accounting rather than from a scan of
//! the segment table. That accounting starts from the checkpoint and moves at
//! each claim or release, including a reservation that has no table bit yet.
//! Recomputing from the table would be a second source of truth.
//!
//! Two counts are reported, not one. Blocks are what data occupies; NODES are
//! what an inode occupies, and a volume can exhaust either — a filesystem full
//! of empty files runs out of nodes with blocks to spare.

use sectors::SectorSource;

use crate::sit;
use crate::summary::SitEntry;
use crate::uapi::RESERVED_NODE_NUM;

use super::Volume;

/// The free-space picture of a mounted volume.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Space {
    /// Blocks the volume covers, past the leading superblock area.
    pub total: u64,
    pub free: u64,
    /// What an unprivileged caller may still use.
    pub avail: u64,
    /// Node slots the table can hold, and how many are unused.
    pub files: u64,
    pub ffree: u64,
    pub block_bytes: u32,
}

impl<S: SectorSource> Volume<S> {
    /// Configured reserved-block pool. # C: O(1)
    pub fn reserved_blocks(&self) -> u64 { self.reserved_blocks }

    /// Live reserved blocks held out of ordinary free space. # C: O(1)
    pub fn current_reserved_blocks(&self) -> u64 { self.current_reserved_blocks }

    /// Change the reserved pool's ceiling without exceeding ordinary space.
    /// # C: O(1)
    pub fn set_reserved_blocks(&mut self, value: u64) -> Result<(), syscall::errno::Errno> {
        let max = self.cp.user_block_count.saturating_sub(u64::from(self.opts.reserve_root));
        if value > max { return Err(syscall::errno::Errno::Einval); }
        self.reserved_blocks = value;
        let free = self.cp.user_block_count.saturating_sub(self.valid_block_count);
        self.current_reserved_blocks = value.min(free);
        Ok(())
    }

    /// Whether the reserved pool is excluded from the reported total. # C: O(1)
    pub fn carve_out(&self) -> bool { self.carve_out }

    /// Set whether the reserved pool is excluded from `statfs.f_blocks`. # C: O(1)
    pub fn set_carve_out(&mut self, on: bool) { self.carve_out = on; }

    /// The counts `statfs` reports. # C: O(1)
    pub fn space(&self) -> Space {
        let start = u64::from(self.sb.segment0_blkaddr);
        let total = self.sb.block_count.saturating_sub(start)
            .saturating_sub(if self.carve_out { self.current_reserved_blocks } else { 0 });
        let user = self.cp.user_block_count;
        let free = user.saturating_sub(self.valid_block_count)
            .saturating_sub(self.current_reserved_blocks);
        let reserved = u64::from(self.opts.reserve_root);
        let avail = free.saturating_sub(reserved);
        let nodes = u64::from(self.max_nid()).saturating_sub(u64::from(RESERVED_NODE_NUM));
        let (files, ffree) = if nodes > user {
            (user, avail)
        } else {
            (nodes, nodes.saturating_sub(u64::from(self.cp.valid_node_count)).min(avail))
        };
        Space { total, free, avail, files, ffree, block_bytes: crate::uapi::BLKSIZE as u32 }
    }

    /// The segment table entry for `segno`, journal first.
    ///
    /// This is the only reader of the segment table, and it exists so an
    /// address can be checked against the segment that owns it rather than
    /// only against the area's bounds.
    /// # C: O(1 block)
    pub fn seg_entry(&self, segno: u32) -> Result<SitEntry, syscall::errno::Errno> {
        use syscall::errno::Errno;
        if segno >= self.sb.segment_count_main { return Err(Errno::Einval); }
        // The loaded table is this mount's own truth once a write has touched
        // it; the medium still holds the state the mount started from.
        if let Some(t) = self.sit.as_ref() {
            if let Some(e) = t.get(segno as usize) { return Ok(e.clone()); }
        }
        if let Some(e) = sit::journalled(&self.sit_journal, segno) { return Ok(e); }
        let blocks = sit::area_blocks(self.sb.segment_count_sit, self.sb.blks_per_seg());
        let addr = sit::block_addr(self.sb.sit_blkaddr, blocks, segno, &self.sit_bitmap);
        let block = self.read_block(addr)?;
        sit::resolve(&self.sit_journal, &block, segno).ok_or(Errno::Eio)
    }

    /// Whether the segment table agrees that `addr` holds live data.
    ///
    /// A block address inside the main area may still be dead — a segment
    /// reuses its blocks — so this is a stronger check than the bounds one,
    /// used where following a stale pointer would read another file's bytes.
    /// # C: O(1 block)
    pub fn block_is_live(&self, addr: u32) -> Result<bool, syscall::errno::Errno> {
        let Some(segno) = self.sb.segno_of(addr) else { return Ok(false) };
        let off = (addr - self.sb.main_blkaddr) % self.sb.blks_per_seg();
        Ok(self.seg_entry(segno)?.is_valid(off as usize))
    }
}
