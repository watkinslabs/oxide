//! Turning a node id into the block its node lives at.
//!
//! Two things stand between the two, and skipping either reads a stale node
//! without any error:
//!
//! - **Every NAT block exists twice.** The table is laid out so the two copies
//!   of a block sit a segment apart, and the checkpoint's NAT version bitmap
//!   says which copy the current checkpoint wrote. Reading the first copy
//!   always would return whatever the previous checkpoint left there.
//! - **The journal wins.** A nid changed recently may have no fresh entry in
//!   either copy at all, because the change was parked in the current
//!   segment's journal instead. The journal is consulted first.

use crate::summary::{NatEntry, NatJournal};
use crate::uapi::*;

/// Which NAT block a nid's entry sits in, and where inside it. # C: O(1)
pub fn locate(nid: u32) -> (u32, usize) {
    let per = NAT_ENTRY_PER_BLOCK as u32;
    (nid / per, (nid % per) as usize * NAT_ENTRY_SIZE)
}

/// Block address of the CURRENT copy of the NAT block holding `nid`.
///
/// The doubling is not a simple "times two": within a segment the two copies
/// interleave segment-wise rather than block-wise, so the offset inside the
/// segment is subtracted back out before the version's segment is added.
/// # C: O(1)
pub fn block_addr(nat_blkaddr: u32, blks_per_seg: u32, nid: u32, bitmap: &[u8]) -> u32 {
    let (block_off, _) = locate(nid);
    let base = nat_blkaddr + (block_off << 1) - (block_off & (blks_per_seg - 1));
    if crate::checkpoint::test_bit(bitmap, block_off as usize) { base + blks_per_seg } else { base }
}

/// The journalled entry for `nid`, if the current segment carries one.
///
/// A journal holds at most a few dozen entries, so the walk is cheaper than
/// the map that would index it.
/// # C: O(journal entries)
pub fn journalled(journal: &NatJournal, nid: u32) -> Option<NatEntry> {
    journal.iter().find(|(n, _)| *n == nid).map(|(_, e)| *e)
}

/// The entry for `nid`, journal first and the table block second.
///
/// `block` is the CURRENT copy of the NAT block, already selected by the
/// version bitmap. Returning the journal's answer when it has one is the whole
/// point: the table copy may be older than the journal by a whole checkpoint.
/// # C: O(journal entries)
pub fn resolve(journal: &NatJournal, block: &[u8], nid: u32) -> Option<NatEntry> {
    if let Some(e) = journalled(journal, nid) { return Some(e); }
    let (_, off) = locate(nid);
    crate::summary::nat_entry(block, off)
}

/// Whether `nid` can name a node at all.
///
/// The first three ids are the node, meta and root inodes' reservations, and
/// `max_nid` is what the table's own size admits. A nid outside that range
/// would index off the end of the table.
/// # C: O(1)
pub fn nid_in_range(nid: u32, max_nid: u32) -> bool { nid > 0 && nid < max_nid }

/// How many node ids the table can hold, given its segment count.
///
/// Half the area is the second copy of every block, which is why the count
/// divides by two.
/// # C: O(1)
pub fn max_nid(segment_count_nat: u32, blks_per_seg: u32) -> u32 {
    let blocks = (segment_count_nat / 2) * blks_per_seg;
    blocks.saturating_mul(NAT_ENTRY_PER_BLOCK as u32)
}

#[cfg(test)]
#[path = "tests/nat.rs"]
mod tests;
