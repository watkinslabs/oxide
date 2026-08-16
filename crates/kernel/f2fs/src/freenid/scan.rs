//! Filling the cache: from a table block, from the journal, and from what the
//! free map already knows.
//!
//! Three sources, and the order between them is the point. The free map is
//! consulted FIRST because it costs no read at all; only when it cannot
//! produce enough ids does a pass go to the table, and the table is walked a
//! bounded number of blocks at a time from a cursor that resumes. The journal
//! is folded in LAST and always: it holds the entries the last checkpoint did
//! not write back, so a table block read a moment ago can still be out of date
//! for the handful of ids the journal carries.
//!
//! Nothing here reads a medium. The caller hands over a block's bytes and the
//! journal's entries, which is what makes a whole build pass — the part that
//! decides which ids are free — checkable without a volume behind it.

use alloc::vec::Vec;

use crate::summary;
use crate::uapi::{NAT_ENTRY_PER_BLOCK, NAT_ENTRY_SIZE, NEW_ADDR, NULL_ADDR};

use super::bitmap::nat_ofs;
use super::limits::{FREE_NID_PAGES, MAX_FREE_NIDS};
use super::state::{Corrupt, FreeNids};

/// The table blocks one build pass would read, and where the cursor lands.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Plan {
    /// First id of each block the pass must actually read, in order. A block
    /// already scanned is absent: its map is believed instead.
    pub reads: Vec<u32>,
    /// The cursor the next pass starts from. It advances over every block the
    /// pass considered, read or not — otherwise a run of already-scanned
    /// blocks would pin the cursor and the walk would never reach the rest of
    /// the table.
    pub next: u32,
}

impl FreeNids {
    /// Which blocks the next build pass reads.
    ///
    /// The cursor is aligned down to a block boundary first: a cursor left
    /// mid-block by an earlier pass would make this one read the block's tail
    /// and mark the whole block scanned, so the ids before the cursor would be
    /// recorded as "known, and not free".
    /// # C: O(FREE_NID_PAGES log blocks)
    pub fn build_plan(&self, max_nid: u32) -> Plan {
        let per = NAT_ENTRY_PER_BLOCK as u32;
        let mut nid = self.next_scan_nid();
        if nid >= max_nid { nid = 0; }
        nid -= nid % per;
        let mut reads = Vec::new();
        for _ in 0..FREE_NID_PAGES {
            // A block this pass has already planned counts as scanned: the
            // real walk marks it the moment it reads it, so a table small
            // enough to wrap inside one pass would otherwise be read twice.
            if !self.block_scanned(nat_ofs(nid)) && !reads.contains(&nid) { reads.push(nid); }
            nid += per;
            if nid >= max_nid { nid = 0; }
        }
        Plan { reads, next: nid }
    }

    /// Fold one table block into the cache.
    ///
    /// `start_nid` is the id the walk begins at, which need not be the block's
    /// first: a cursor can land inside a block. The block is marked scanned
    /// before anything else, because an update against an unscanned block is
    /// dropped and every bit this establishes would go with it.
    /// # C: O(entries in a block)
    pub fn scan_nat_block(&mut self, block: &[u8], start_nid: u32, max_nid: u32)
        -> Result<(), Corrupt> {
        let per = NAT_ENTRY_PER_BLOCK;
        self.bits.mark_scanned(nat_ofs(start_nid));
        let mut nid = start_nid;
        let mut i = (start_nid % per as u32) as usize;
        while i < per {
            if nid >= max_nid { break; }
            let e = summary::nat_entry(block, i * NAT_ENTRY_SIZE).ok_or(Corrupt::ShortBlock)?;
            match e.block_addr {
                // Reserved-but-unwritten is an in-memory state. On the medium
                // it means the table itself is damaged, and believing the
                // entry either way would be a guess.
                NEW_ADDR => return Err(Corrupt::ReservedAddr),
                NULL_ADDR => { self.add(nid, max_nid, true, Some(true)); }
                _ => self.bits.update(nid, false, true),
            }
            i += 1;
            nid += 1;
        }
        Ok(())
    }

    /// Fold the node-table journal in: `(nid, block_addr)` per entry.
    ///
    /// The journal OVERRIDES the table, in both directions. An id the journal
    /// frees is free however the table reads, and an id the journal gives an
    /// address to is in use even if the table block still calls it empty.
    /// # C: O(entries log ids)
    pub fn scan_journal(&mut self, entries: impl Iterator<Item = (u32, u32)>, max_nid: u32) {
        for (nid, addr) in entries {
            if addr == NULL_ADDR { self.add_no_update(nid, max_nid, true, None); }
            else { self.remove(nid); }
        }
    }

    /// Re-walk the free map for ids the cache is no longer holding.
    ///
    /// This is the pass that costs nothing. The map remembers what earlier
    /// table reads found; the entries themselves may since have been handed
    /// out, shrunk away or never inserted, and every one of those can be put
    /// back without touching the medium. It stops at the ceiling because past
    /// that a shrink would only undo the work.
    /// # C: O(ids the map calls free, log ids each)
    pub fn scan_free_nid_bits(&mut self, max_nid: u32) {
        for ofs in self.bits.blocks_with_free() {
            for nid in self.bits.free_in_block(ofs) {
                self.add_no_update(nid, max_nid, true, None);
                if self.free_count() >= MAX_FREE_NIDS { return; }
            }
        }
    }
}

#[cfg(test)]
#[path = "../tests/freenid/scan.rs"]
mod tests;
