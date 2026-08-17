//! Node ids: taking one, giving one back, and keeping the cache that holds
//! them true.
//!
//! Everything the free-id cache needs from a medium lives here, and nothing
//! else does. The cache itself is pure — it is handed a table block's bytes
//! and the entries the journal carries — so the part that decides WHICH id a
//! file gets is checkable without a volume, and this file is only the reads
//! that feed it.
//!
//! The order matters more than anything else in it. A table block read from
//! the medium is BEHIND: an id this mount has taken still reads as free there
//! until a checkpoint says otherwise, so every refill folds in the journal and
//! then this mount's own unwritten changes on top of what it read. Skipping
//! either would hand out an id something is already using, and one file's
//! node would be written over another's.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::summary::NatEntry;
use crate::uapi::*;

use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Give a node id back to the cache that handed it out.
    ///
    /// Which way depends on what the id was doing. One that was handed out and
    /// never became a node goes back through the failure path, which returns
    /// it to the TAIL of the order — something may still be holding it and it
    /// is the last id that should be reused. One that WAS a live node is newly
    /// free and joins the order like any other.
    ///
    /// `RAM_UNBOUNDED` is what the failure path is told about memory. Nothing
    /// at this layer can ask the machine how much it has, and the honest
    /// figure for "the question cannot be asked here" is the one that never
    /// makes the cache drop an id it could have kept.
    /// # C: O(log ids)
    pub(crate) fn return_nid(&mut self, nid: u32) {
        const RAM_UNBOUNDED: u64 = u64::MAX;
        let max = self.max_nid();
        match self.free_nids.state_of(nid) {
            Some(crate::freenid::NidState::Prealloc) =>
                self.free_nids.alloc_failed(nid, RAM_UNBOUNDED),
            _ => { self.free_nids.add(nid, max, false, None); }
        }
    }

    /// Whether `nid` has been handed out but never made into a node.
    ///
    /// The one thing that tells a claimed id from a node changed and not yet
    /// placed: both read as the no-address-yet marker in the node table, and
    /// they are opposites for charging, counting and release.
    /// # C: O(log ids)
    pub(crate) fn nid_unwritten(&self, nid: u32) -> bool {
        matches!(self.free_nids.state_of(nid), Some(crate::freenid::NidState::Prealloc))
    }

    /// A node id nothing is using.
    ///
    /// Taken from the cache of known-free ids rather than by walking the table
    /// from a cursor. The walk is what the cache replaces: it reads a table
    /// block per id considered and the cursor only moves forward, so a volume
    /// whose free ids sit behind the cursor reads the whole table — thousands
    /// of blocks — to find one id, once per file created.
    ///
    /// Each refill folds in the journal AND this mount's own unwritten
    /// changes, both of which override the table. Without that an id this
    /// mount freed a moment ago would still read as in use, and — the failure
    /// that matters — an id it has already handed out would read as free and
    /// be handed out twice, making one node overwrite another.
    /// # C: O(log ids), plus a bounded table read when the cache runs dry
    pub(crate) fn alloc_nid(&mut self) -> Result<u32, Errno> {
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::AllocNid) {
            return Err(Errno::Enospc);
        }
        let max = self.max_nid();
        // Bounded by the whole table: a pass advances the cursor over a fixed
        // number of blocks, so this many have seen all of it and a further one
        // would only repeat the first.
        let per = crate::uapi::NAT_ENTRY_PER_BLOCK as u32;
        let blocks = max.div_ceil(per.max(1));
        let passes = blocks.div_ceil(crate::freenid::FREE_NID_PAGES as u32) + 1;
        for _ in 0..passes {
            if let Some(nid) = self.free_nids.alloc() {
                self.next_free_nid = nid + 1;
                // Claimed the instant it is handed out: an id that is free but
                // unrecorded would be handed out again by the very next call.
                self.nat_dirty
                    .insert(nid, NatEntry { version: 0, ino: nid, block_addr: NEW_ADDR });
                return Ok(nid);
            }
            if self.free_nids.available_nids() == 0 { break; }
            self.build_free_nids()?;
        }
        Err(Errno::Enospc)
    }

    /// Read the next few table blocks into the free-id cache.
    ///
    /// The free map is re-walked first because it costs nothing: it remembers
    /// what earlier reads found, and ids it still calls free may since have
    /// been handed back or shrunk away. Only when that produces too few is the
    /// medium touched at all.
    /// # C: O(FREE_NID_PAGES blocks)
    pub(crate) fn build_free_nids(&mut self) -> Result<(), Errno> {
        let max = self.max_nid();
        self.free_nids.scan_free_nid_bits(max);
        if self.free_nids.need_build() {
            let plan = self.free_nids.build_plan(max);
            for start in plan.reads {
                let addr = crate::nat::block_addr(self.sb.nat_blkaddr, self.sb.blks_per_seg(),
                                                  start, &self.nat_bitmap);
                let block = self.read_block(addr)?;
                self.free_nids.scan_nat_block(&block, start, max).map_err(|_| Errno::Eio)?;
            }
            self.free_nids.set_next_scan_nid(plan.next);
        }
        self.fold_pending_nids(max);
        Ok(())
    }

    /// Fold in everything that overrides the table, freshest last.
    ///
    /// The journal holds entries the last checkpoint parked instead of writing
    /// back; the dirty set holds what THIS mount has changed and has not
    /// checkpointed at all. Both beat the table block, and the dirty set beats
    /// the journal — the same order every read of a node id already uses.
    /// # C: O(journalled + dirty entries, log ids each)
    fn fold_pending_nids(&mut self, max: u32) {
        let journal: alloc::vec::Vec<(u32, u32)> =
            self.nat_journal.iter().map(|(n, e)| (*n, e.block_addr)).collect();
        self.free_nids.scan_journal(journal.into_iter(), max);
        let dirty: alloc::vec::Vec<(u32, u32)> =
            self.nat_dirty.iter().map(|(n, e)| (*n, e.block_addr)).collect();
        self.free_nids.scan_journal(dirty.into_iter(), max);
    }

    /// Ids held free, ids handed out and not yet settled, and ids the volume
    /// has left — the three figures the report publishes. # C: O(1)
    pub fn free_nid_counts(&self) -> (u32, u32, u32) {
        (self.free_nids.free_count(), self.free_nids.alloc_count(),
         self.free_nids.available_nids())
    }

    /// Whether the cache is holding `nid` as free — as against handed out, or
    /// not held at all. What a caller checking that a released id came back
    /// asks: it will be handed out once the ids ahead of it are, and the
    /// question is whether it is in the order at all. # C: O(log ids)
    pub fn nid_is_cached_free(&self, nid: u32) -> bool {
        self.free_nids.state_of(nid) == Some(crate::freenid::NidState::Free)
    }

    /// Bytes the free-id cache is holding. # C: O(1)
    pub fn free_nid_bytes(&self) -> u64 { self.free_nids.mem_bytes() }

    /// The share of memory the free-id cache is held within. # C: O(1)
    pub fn nid_ram_thresh(&self) -> u32 { self.free_nids.ram_thresh }

    /// # C: O(1)
    pub fn set_nid_ram_thresh(&mut self, v: u32) { self.free_nids.ram_thresh = v; }
}

#[cfg(test)]
#[path = "../tests/nidwire.rs"]
mod tests;
