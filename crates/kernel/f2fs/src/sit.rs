//! The segment information table: how much of each segment is live.
//!
//! Same doubling as the node table and the same version bitmap selecting a
//! copy, but the arithmetic differs: SIT blocks are indexed straight by
//! segment number and the second copy sits one whole half-area further on,
//! where NAT's two copies interleave inside a segment. Using one rule for both
//! reads the wrong block and reports a segment's occupancy as another's.

use crate::summary::{SitEntry, SitJournal};
use crate::uapi::*;

/// Which SIT block a segment's entry sits in, and where inside it.
/// # C: O(1)
pub fn locate(segno: u32) -> (u32, usize) {
    let per = SIT_ENTRY_PER_BLOCK as u32;
    (segno / per, (segno % per) as usize * SIT_ENTRY_SIZE)
}

/// Blocks one copy of the table occupies. # C: O(1)
pub fn area_blocks(segment_count_sit: u32, blks_per_seg: u32) -> u32 {
    (segment_count_sit / 2) * blks_per_seg
}

/// Block address of the CURRENT copy of the SIT block holding `segno`.
/// # C: O(1)
pub fn block_addr(sit_blkaddr: u32, sit_blocks: u32, segno: u32, bitmap: &[u8]) -> u32 {
    let (block_off, _) = locate(segno);
    let base = sit_blkaddr + block_off;
    if crate::checkpoint::test_bit(bitmap, block_off as usize) { base + sit_blocks } else { base }
}

/// The journalled entry for `segno`, if the current segment carries one.
/// # C: O(journal entries)
pub fn journalled(journal: &SitJournal, segno: u32) -> Option<SitEntry> {
    journal.iter().find(|(s, _)| *s == segno).map(|(_, e)| e.clone())
}

/// The entry for `segno`, journal first and the table block second.
/// # C: O(journal entries)
pub fn resolve(journal: &SitJournal, block: &[u8], segno: u32) -> Option<SitEntry> {
    if let Some(e) = journalled(journal, segno) { return Some(e); }
    let (_, off) = locate(segno);
    crate::summary::sit_entry(block, off)
}

/// Whether an entry's own count agrees with its own bitmap.
///
/// The two are written together and a checker that trusts the count while
/// reading the bitmap — or the reverse — reports a segment as fuller or
/// emptier than it is.
/// # C: O(SIT_VBLOCK_MAP_SIZE)
pub fn self_consistent(e: &SitEntry, blks_per_seg: u32) -> bool {
    let counted: u32 = e.valid_map.iter().map(|b| b.count_ones()).sum();
    u32::from(e.valid_blocks()) == counted && u32::from(e.valid_blocks()) <= blks_per_seg
}

#[cfg(test)]
#[path = "tests/sit.rs"]
mod tests;
