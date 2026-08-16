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
        let sit = self.sit.as_mut().ok_or(Errno::Eio)?;
        let e = sit.get_mut(segno as usize).ok_or(Errno::Eio)?;
        let was = e.valid_map[off / 8] & (1 << (off % 8)) != 0;
        if was == live { return Ok(()); }
        if live {
            e.valid_map[off / 8] |= 1 << (off % 8);
            e.vblocks = e.vblocks.wrapping_add(1);
            self.valid_block_count += 1;
        } else {
            e.valid_map[off / 8] &= !(1 << (off % 8));
            e.vblocks = e.vblocks.wrapping_sub(1);
            self.valid_block_count = self.valid_block_count.saturating_sub(1);
        }
        self.sit_dirty.insert(segno);
        Ok(())
    }

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
        (0..n)
            .map(|i| (hint + 1 + i) % n)
            .find(|&s| self.seg_valid(s) == 0 && !self.is_current(s))
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
            if self.is_current(s) { continue; }
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
    /// where there is only a writer.
    /// # C: O(main segments)
    pub(crate) fn free_segment_count(&self) -> u32 {
        (0..self.sb.segment_count_main)
            .filter(|&s| self.seg_valid(s) == 0 && !self.is_current(s))
            .count() as u32
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
