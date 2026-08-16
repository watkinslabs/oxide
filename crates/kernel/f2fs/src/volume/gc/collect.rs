//! Cleaning a segment, and cleaning until there is room again.
//!
//! Without this the volume runs out of space while reporting free blocks. Every
//! write is out of place, so a file rewritten in place leaves its old block
//! dead where it lies; the segment holding it is neither free — a free segment
//! has nothing live in it — nor usable by the append allocator, which only ever
//! opens empty segments. The dead blocks are real free space that nothing can
//! reach until something moves the survivors out and hands the segment back.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::*;

use super::live;
use super::victim::{self, Policy, SegInfo};
use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
    /// The segment table as victim selection sees it. # C: O(main segments)
    pub(crate) fn seg_table(&self) -> Vec<SegInfo> {
        self.segments()
            .iter()
            .enumerate()
            .map(|(i, e)| SegInfo {
                segno: i as u32,
                live: e.valid_blocks(),
                mtime: e.mtime,
                current: self.is_current(i as u32),
            })
            .collect()
    }

    /// The segment worth cleaning next under `policy`. # C: O(main segments)
    pub fn pick_victim(&self, policy: Policy, skip: &[u32]) -> Option<u32> {
        victim::pick(&self.seg_table(), self.sb.blks_per_seg() as u16, policy, skip)
    }

    /// Clean `segno`: move out everything still live in it.
    ///
    /// Returns the blocks moved. A segment can come back with blocks still in
    /// it — a block the table calls live that no owner claims is left exactly
    /// where it is, because moving it would write an address into a file that
    /// does not want one.
    /// # C: O(blocks per segment) blocks read and rewritten
    pub fn gc_segment(&mut self, segno: u32) -> Result<u32, Errno> {
        self.writable_or_err()?;
        self.load_segments()?;
        if segno >= self.sb.segment_count_main { return Err(Errno::Einval); }
        // A log is still appending here; its own summary entries are in memory
        // and the block after the one being read is about to be handed out.
        if self.is_current(segno) { return Err(Errno::Ebusy); }
        let per_seg = self.sb.blks_per_seg();
        let sum = self.read_block(sum_block_addr(self.sb.ssa_blkaddr, segno))?;
        let nodes = live::holds_nodes(&sum);
        let base = self.sb.main_blkaddr + segno * per_seg;
        let mut moved = 0u32;
        let mut stale: Vec<u32> = Vec::new();
        for off in 0..per_seg as usize {
            let addr = base + off as u32;
            let bit = self.segments().get(segno as usize).is_some_and(|e| e.is_valid(off));
            let Some(s) = live::entry(&sum, off) else { continue };
            let owner = if nodes { self.node_addr(s.nid).ok() } else { self.owner_addr(&s) };
            if !live::alive(bit, &s, owner, addr) { continue; }
            if nodes { self.migrate_node(s.nid)?; } else { self.migrate_data(addr, &s)?; stale.push(addr); }
            moved += 1;
        }
        // Only now: while any of these bits stood the segment could not be
        // opened by a log, which is what kept the copies above reading the
        // blocks they meant to read.
        for addr in stale { self.release_block(addr)?; }
        Ok(moved)
    }

    /// Clean the single best victim. # C: O(blocks per segment)
    pub fn gc_one_segment(&mut self) -> Result<Option<u32>, Errno> {
        self.writable_or_err()?;
        self.load_segments()?;
        let Some(segno) = self.pick_victim(Policy::Greedy, &[]) else { return Ok(None) };
        self.gc_segment(segno)?;
        Ok(Some(segno))
    }

    /// Clean until `target` segments are free, or until nothing is worth
    /// cleaning. Returns the segments emptied.
    ///
    /// A victim is never tried twice in one call. One that would not empty —
    /// because a block in it is live by the table and disowned by every node —
    /// would otherwise be chosen again on the next pass and the cleaner would
    /// never stop.
    /// # C: O(segments cleaned * blocks per segment)
    pub fn collect(&mut self, target: u32) -> Result<u32, Errno> {
        self.collect_with(Policy::Greedy, target)
    }

    /// The same, under a stated policy. # C: O(segments cleaned * blocks)
    pub fn collect_with(&mut self, policy: Policy, target: u32) -> Result<u32, Errno> {
        self.writable_or_err()?;
        self.load_segments()?;
        let mut skip: Vec<u32> = Vec::new();
        let mut freed = 0u32;
        while self.free_segment_count() < target {
            let Some(segno) = self.pick_victim(policy, &skip) else { break };
            self.gc_segment(segno)?;
            if self.seg_valid(segno) == 0 { freed += 1; }
            skip.push(segno);
        }
        Ok(freed)
    }
}
