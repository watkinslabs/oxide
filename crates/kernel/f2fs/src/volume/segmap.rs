//! Which blocks of the main area are live, and which segments are free.
//!
//! This is the allocator's truth. Every block written marks a bit and raises a
//! count; every block released clears one and lowers it. Getting the pairing
//! wrong does not fail at the time — it produces a segment the allocator
//! believes is free while a file still points into it, and the next write
//! overwrites live data.
//!
//! The table is loaded whole on the first write and not before: a read-only
//! mount never needs it, and it is one entry per segment of the volume.
//!
//! A segment that empties is NOT free. It becomes PREFREE, and only the next
//! checkpoint hands it to the allocator. The checkpoint on the medium still
//! describes the blocks that were in it, so reusing one immediately would let
//! a write land on top of state a crash would otherwise recover to — the
//! blocks are dead in memory and live on the medium until a checkpoint says
//! otherwise. Prefree is in memory only: a mount reads the segment table and
//! every empty segment is free again, because the checkpoint it was read from
//! is the one that retired those references.

use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::sit;
use crate::summary::SitEntry;
use crate::uapi::*;

use super::Volume;

/// A blank entry, for a segment nothing has been written to.
pub fn empty_entry() -> SitEntry {
    SitEntry { vblocks: 0, valid_map: [0u8; SIT_VBLOCK_MAP_SIZE], mtime: 0 }
}

/// The segment-management state a mount keeps in memory and never writes.
///
/// None of it is on the medium and none of it needs to be: the prefree map is
/// empty at mount by construction, and the two clock fields exist to turn the
/// caller's wall clock into the volume's own elapsed seconds, which is what a
/// segment timestamp is measured in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SegState {
    /// Segments emptied since the last checkpoint. Not free until one lands.
    pub prefree: BTreeSet<u32>,
    /// The volume's age at mount, as the checkpoint recorded it.
    pub elapsed_base: u64,
    /// The wall clock as it read when this mount first learned one. Segment
    /// timestamps count from here, so a volume never told the time keeps the
    /// age it was mounted with rather than jumping to the epoch.
    pub mounted_clock: Option<u64>,
    /// Whether the cleaner is moving blocks. A migration is not a write as
    /// far as age is concerned: the data is exactly as old as it was, and
    /// stamping it fresh would make cleaned segments look new and hide them
    /// from the very policy that chose them.
    pub gc_moving: bool,
    /// The timestamp a migration carries across, being the victim's.
    pub gc_src_mtime: u64,
    /// Whether the cleaner is already running, so that a checkpoint taken to
    /// reclaim prefree segments cannot re-enter it.
    pub gc_running: bool,
    /// Where the next victim search resumes, so successive searches sweep the
    /// volume instead of re-costing the same low-numbered segments.
    pub gc_cursor: u32,
    /// The wall clock as it read when the last checkpoint landed. The
    /// periodic checkpoint is measured from here, so a mount that has just
    /// written one is not asked for another a moment later.
    pub last_cp_clock: u64,
}

impl SegState {
    /// The state a fresh mount starts from. # C: O(1)
    pub fn at_mount(elapsed: u64) -> Self {
        Self { elapsed_base: elapsed, ..Self::default() }
    }
}

impl<S: SectorSource> Volume<S> {
    /// Load the whole segment table, once.
    ///
    /// The journal overrides the table here exactly as it does on a read: a
    /// segment whose entry was parked in the journal is more recent there.
    /// # C: O(segment table blocks)
    pub(crate) fn load_segments(&mut self) -> Result<(), Errno> {
        if self.sit.is_some() { return Ok(()); }
        let segs = self.sb.segment_count_main;
        let blocks = sit::area_blocks(self.sb.segment_count_sit, self.sb.blks_per_seg());
        let mut out = Vec::with_capacity(segs as usize);
        let mut cached: Option<(u32, Vec<u8>)> = None;
        for segno in 0..segs {
            if let Some(e) = sit::journalled(&self.sit_journal, segno) { out.push(e); continue; }
            let (block_off, off) = sit::locate(segno);
            if cached.as_ref().map(|(o, _)| *o) != Some(block_off) {
                let addr = sit::block_addr(self.sb.sit_blkaddr, blocks, segno, &self.sit_bitmap);
                cached = Some((block_off, self.read_block(addr)?));
            }
            let block = &cached.as_ref().expect("just filled").1;
            out.push(crate::summary::sit_entry(block, off).ok_or(Errno::Eio)?);
        }
        self.sit = Some(out);
        Ok(())
    }

    /// The loaded table. # C: O(1)
    pub(crate) fn segments(&self) -> &[SitEntry] {
        self.sit.as_deref().unwrap_or(&[])
    }

    /// Mark the block at `addr` live or dead, and keep every count that
    /// depends on it in step.
    ///
    /// A `NULL_ADDR` or `NEW_ADDR` is not a block and is ignored; releasing
    /// one would lower a count nothing raised.
    /// # C: O(1)
    pub(crate) fn update_seg(&mut self, addr: u32, live: bool) -> Result<(), Errno> {
        if crate::node::is_hole(addr) { return Ok(()); }
        let Some(segno) = self.sb.segno_of(addr) else { return Err(Errno::Eio) };
        let off = ((addr - self.sb.main_blkaddr) % self.sb.blks_per_seg()) as usize;
        {
            let sit = self.sit.as_ref().ok_or(Errno::Eio)?;
            let e = sit.get(segno as usize).ok_or(Errno::Eio)?;
            if (e.valid_map[off / 8] & (1 << (off % 8)) != 0) == live { return Ok(()); }
        }
        // Before the count moves, because the timestamp is an average over the
        // blocks the segment already holds: taking it after would weigh the
        // new block into its own average.
        if let Some(m) = self.stamp_for(live) { self.stamp_seg_mtime(segno, m); }
        let sit = self.sit.as_mut().ok_or(Errno::Eio)?;
        let e = sit.get_mut(segno as usize).ok_or(Errno::Eio)?;
        if live {
            e.valid_map[off / 8] |= 1 << (off % 8);
            e.vblocks = e.vblocks.wrapping_add(1);
            self.valid_block_count += 1;
        } else {
            e.valid_map[off / 8] &= !(1 << (off % 8));
            e.vblocks = e.vblocks.wrapping_sub(1);
            self.valid_block_count = self.valid_block_count.saturating_sub(1);
            let emptied = e.valid_blocks() == 0;
            // A log's own segment is never prefree: the log is still
            // appending to it, and the blocks it hands out next would be
            // taken from a segment the allocator had been told not to touch.
            if emptied && !self.is_current(segno) { self.segstate.prefree.insert(segno); }
        }
        self.sit_dirty.insert(segno);
        Ok(())
    }

    /// The timestamp a block change stamps its segment with, or `None` when
    /// it stamps none.
    ///
    /// A migration leaves both ends alone but the destination, which inherits
    /// the victim's age; every other change is a write, and a write is now.
    /// # C: O(1)
    fn stamp_for(&self, live: bool) -> Option<u64> {
        match (self.segstate.gc_moving, live) {
            (true, true) => Some(self.segstate.gc_src_mtime),
            (true, false) => None,
            (false, _) => Some(self.seg_mtime_now()),
        }
    }

    /// The volume's age right now, in the seconds a segment timestamp counts.
    ///
    /// The base is what the checkpoint recorded at mount; the offset is how
    /// long this mount has been told it has been running. A mount never told
    /// the time reports the base, which is the same answer as a clock that
    /// has not moved.
    ///
    /// A clock set BACKWARDS during the mount takes the volume back with it
    /// rather than freezing its age: ages are only ever compared against each
    /// other, and a run of segments stamped with a time that cannot be
    /// reached again would sit at the top of the ordering forever.
    /// # C: O(1)
    pub(crate) fn seg_mtime_now(&self) -> u64 {
        let base = self.segstate.mounted_clock.unwrap_or(self.clock);
        if self.clock >= base {
            self.segstate.elapsed_base.saturating_add(self.clock - base)
        } else {
            self.segstate.elapsed_base.saturating_sub(base - self.clock)
        }
    }

    /// Fold `mtime` into `segno`'s timestamp.
    ///
    /// A segment holds blocks written at different moments, so its timestamp
    /// is the mean over them rather than the last one: one recent block in an
    /// otherwise ancient segment must not make the whole segment look new to
    /// a policy that is trying to find the old ones.
    /// # C: O(1)
    fn stamp_seg_mtime(&mut self, segno: u32, mtime: u64) {
        let Some(sit) = self.sit.as_mut() else { return };
        let Some(e) = sit.get_mut(segno as usize) else { return };
        let held = u64::from(e.valid_blocks());
        e.mtime = if e.mtime == 0 {
            mtime
        } else {
            (e.mtime.saturating_mul(held).saturating_add(mtime)) / (held + 1)
        };
    }

    /// The timestamp `segno` carries. # C: O(1)
    pub(crate) fn seg_mtime(&self, segno: u32) -> u64 {
        self.segments().get(segno as usize).map(|e| e.mtime).unwrap_or(0)
    }

    /// Whether `segno` is empty but not yet handed back. # C: O(log prefree)
    pub(crate) fn is_prefree(&self, segno: u32) -> bool {
        self.segstate.prefree.contains(&segno)
    }

    /// Segments waiting for a checkpoint to become free again. # C: O(1)
    pub fn prefree_count(&self) -> u32 { self.segstate.prefree.len() as u32 }

    /// Note that the log holding `segno` has stopped writing into it.
    ///
    /// A segment emptied WHILE a log held it open was not made prefree then —
    /// the log was still appending. It becomes prefree the moment the log
    /// leaves, or it would go straight back into the allocator with the
    /// checkpoint on the medium still pointing into it. Called by the log
    /// that is leaving, which is why a segment still recorded as that log's
    /// own is retired anyway.
    /// # C: O(1)
    pub(crate) fn retire_segment(&mut self, segno: u32) {
        if segno == NULL_SEGNO { return; }
        if self.seg_valid(segno) == 0 { self.segstate.prefree.insert(segno); }
    }

    /// Hand every prefree segment back to the allocator, and restart the
    /// periodic-checkpoint clock.
    ///
    /// Called by the checkpoint, and by nothing else: the checkpoint being
    /// written is exactly the event that retires the references those
    /// segments were being held against, and the same event is what the
    /// interval to the next periodic one is measured from. Both here so the
    /// two cannot drift apart — an interval restarted anywhere else would be
    /// restarted by something that is not a checkpoint.
    /// # C: O(prefree)
    pub(crate) fn clear_prefree(&mut self) {
        self.segstate.prefree.clear();
        self.segstate.last_cp_clock = self.clock;
    }

    /// The wall clock as this mount last read it, in seconds.
    ///
    /// Zero for a mount nobody has told the time to, which is the same answer
    /// as a clock that has not started: every consumer here compares two
    /// readings, so a mount with no clock reads as one that is not ageing.
    /// # C: O(1)
    pub fn now_secs(&self) -> u64 { self.clock }

    /// Live blocks in `segno`. # C: O(1)
    pub(crate) fn seg_valid(&self, segno: u32) -> u16 {
        self.segments().get(segno as usize).map(|e| e.valid_blocks()).unwrap_or(0)
    }

    /// Whether `segno` is open in one of the logs. A log's own segment is
    /// never a candidate for allocation elsewhere. # C: O(logs)
    pub(crate) fn is_current(&self, segno: u32) -> bool {
        self.curseg.iter().any(|c| c.segno == segno)
    }

    /// A segment with no live blocks at all, for a fresh log.
    ///
    /// The search starts past the hint so consecutive allocations spread out
    /// rather than fighting over the lowest free segment.
    /// # C: O(main segments)
    pub(crate) fn find_free_seg(&self, hint: u32) -> Option<u32> {
        let n = self.sb.segment_count_main;
        (0..n).map(|i| (hint + 1 + i) % n).find(|&s| self.seg_is_free(s))
    }

    /// Whether the allocator may open `segno`.
    ///
    /// Empty is not enough. A segment a log holds is being filled, and a
    /// prefree one is empty only in memory — the checkpoint on the medium
    /// still names its blocks.
    /// # C: O(logs + log prefree)
    pub(crate) fn seg_is_free(&self, segno: u32) -> bool {
        self.seg_valid(segno) == 0 && !self.is_current(segno) && !self.is_prefree(segno)
    }

    /// A partly-used segment to recycle, and the first free block in it.
    ///
    /// A segment that is empty is not a recycling candidate — that is what
    /// opening a fresh one is for — and one that is full has nothing to give.
    /// # C: O(main segments)
    pub(crate) fn find_victim_seg(&self, hint: u32) -> Option<(u32, u16)> {
        let n = self.sb.segment_count_main;
        let per = self.sb.blks_per_seg() as u16;
        for i in 0..n {
            let s = (hint + 1 + i) % n;
            if self.is_current(s) || self.is_prefree(s) { continue; }
            let live = self.seg_valid(s);
            if live == 0 || live >= per { continue; }
            if let Some(off) = self.first_free_block(s) { return Some((s, off)); }
        }
        None
    }

    /// The first block of `segno` nothing is using. # C: O(blocks per segment)
    pub(crate) fn first_free_block(&self, segno: u32) -> Option<u16> {
        self.next_free_block(segno, 0)
    }

    /// The first block of `segno` at or after `from` that nothing is using.
    /// # C: O(blocks per segment)
    pub(crate) fn next_free_block(&self, segno: u32, from: u16) -> Option<u16> {
        let e = self.segments().get(segno as usize)?;
        (from..self.sb.blks_per_seg() as u16).find(|&i| !e.is_valid(i as usize))
    }

    /// Segments the allocator could still hand out, which is what the
    /// checkpoint records and what the cleaner measures itself against.
    ///
    /// A segment a log holds open is NOT free however empty it is: the log
    /// will fill it, and counting it would tell the cleaner there is room
    /// where there is only a writer. Neither is a prefree one, which is why
    /// the cleaner has to take a checkpoint to make the space it just found
    /// usable.
    /// # C: O(main segments)
    pub(crate) fn free_segment_count(&self) -> u32 {
        (0..self.sb.segment_count_main).filter(|&s| self.seg_is_free(s)).count() as u32
    }

    /// The segment table entries this mount has changed. # C: O(dirty)
    pub(crate) fn dirty_segments(&self) -> Vec<(u32, SitEntry)> {
        let mut out: Vec<(u32, SitEntry)> = self
            .sit_dirty
            .iter()
            .filter_map(|&s| self.segments().get(s as usize).map(|e| (s, e.clone())))
            .collect();
        out.sort_by_key(|(s, _)| *s);
        out
    }
}

/// A segment table block holding `entries` at their own slots. # C: O(entries)
pub fn sit_block(entries: &[(u32, SitEntry)]) -> Vec<u8> {
    let mut b = vec![0u8; BLKSIZE];
    for (segno, e) in entries {
        let (_, at) = sit::locate(*segno);
        b[at + SIT_VBLOCKS..at + SIT_VBLOCKS + 2].copy_from_slice(&e.vblocks.to_le_bytes());
        b[at + SIT_VALID_MAP..at + SIT_VALID_MAP + SIT_VBLOCK_MAP_SIZE]
            .copy_from_slice(&e.valid_map);
        b[at + SIT_MTIME..at + SIT_MTIME + 8].copy_from_slice(&e.mtime.to_le_bytes());
    }
    b
}

#[cfg(test)]
#[path = "../tests/segmap.rs"]
mod tests;
