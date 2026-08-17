//! Putting the mount's dirty node blocks on the medium, and choosing where.
//!
//! A node change does not allocate. It counts the node against the volume,
//! charges its owner, records the id in the node table with no address yet,
//! and leaves the block in the node mapping; the segment, the log and the
//! block address are decided HERE. That is what makes a transaction's nodes
//! one run of one log instead of a scattered block per change, and it is why
//! the reference chooses a node's address at writeback and nowhere else.
//!
//! Three things must NOT happen here and each one is a defect if it does:
//!
//! - The room must not be asked for again. It was taken when the node was
//!   changed, so a second demand at writeback refuses a node the caller was
//!   already told it had — and there is nothing to unwind it to.
//! - The log must not be taken from the caller. There is no caller: the flush
//!   point that reaches this page holds nothing about which node it is. The
//!   log is read off the block's own footer, which is where the reference
//!   reads it from and the reason the temperature is stamped into the block.
//! - A node released while dirty must not be written. Its id is free and its
//!   table entry says so; placing its stale block would put a live bit in the
//!   segment table under a node nothing names.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use block::pagecache::PageOut;
use block::types::{BlockError, KResult};

use crate::filemap::NodeCache;
use crate::node::footer;
use crate::summary::NatEntry;
use crate::uapi::*;

use super::curseg::{self, Summary};
use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Place one node block, reporting the address it took.
    /// # C: O(main segments) worst case
    pub(crate) fn writeback_node_block(&mut self, nid: u32, block: &[u8]) -> Result<u32, Errno> {
        self.writable_or_err()?;
        if block.len() != BLKSIZE { return Err(Errno::Einval); }
        let f = footer::parse(block).ok_or(Errno::Eio)?;
        if f.nid != nid { return Err(Errno::Eio); }
        let old = self.node_addr(nid).unwrap_or(NULL_ADDR);
        // The node was released while its page was still dirty. The id is back
        // in the free pool and the table says the node is gone, so writing the
        // block would resurrect it as a live block nothing names.
        if old == NULL_ADDR { return Err(Errno::Enoent); }
        let kind = curseg::node_kind_of(&f);
        let sum = Summary { nid, version: 0, ofs_in_node: 0 };
        // `allocate_block`, not `allocate_new_block`: the room a node needs was
        // taken when the node was changed. Asking again would refuse, at
        // writeback, a node the caller was already told it had.
        let addr = self.allocate_block(kind, sum, old)?;
        let mut out = block.to_vec();
        let at = NODE_FOOTER_OFF;
        out[at + FOOTER_CP_VER..at + FOOTER_CP_VER + 8]
            .copy_from_slice(&self.cp.version.to_le_bytes());
        // The chain a crash is recovered from is built here: each node names
        // the block the log will hand out NEXT, so a walk forward from the
        // checkpoint's position reaches everything written after it. Stamping
        // the block's own address instead makes every chain one link long and
        // no crash tail recoverable. Read after the allocation, which has
        // already advanced the log and opened a fresh segment if this write
        // filled one. Both words sit in the footer, which an inode's checksum
        // does not cover, so the block stays sealed as it was.
        let next = self.curseg[curseg::log_for(kind, self.opts.active_logs)]
            .next_addr(self.sb.main_blkaddr);
        out[at + FOOTER_NEXT_BLKADDR..at + FOOTER_NEXT_BLKADDR + 4]
            .copy_from_slice(&next.to_le_bytes());
        // A node block sits in the main area beside file data, so its address
        // does not say what it is. It is metadata all the same: every data
        // block under it is unreachable until the node naming it lands.
        self.write_block_flags(addr, &out, block::flags::META)?;
        // A node block belongs to a file, and it is that file's `fsync` that
        // fences the member it landed on. The owner is in the block's own footer
        // — an inode block names itself — so no caller has to carry it here.
        self.note_file_write(f.ino, addr);
        {
            use crate::stats::iostat::Io;
            self.io_account(self.io_gc_kind(Io::FsNode, Io::FsGcNode), BLKSIZE as u64, false);
        }
        self.nat_dirty.insert(nid, NatEntry { version: 0, ino: f.ino, block_addr: addr });
        // The count the node was charged when it was changed is the count this
        // block just took up. Released after the segment update raised it, so
        // the two never overlap and never both miss.
        if old == NEW_ADDR { self.release_reservation(); }
        self.dirty = true;
        Ok(addr)
    }

    /// Place ONE node now, by id, and keep its page — clean.
    ///
    /// What a flush point that cares about the ORDER of its nodes needs — the
    /// chain an `fsync` leaves is read forward from where the log stood, so
    /// the inode has to reach the medium before the nodes under it, and no
    /// batch entry point can express that because the mapping picks the batch.
    ///
    /// The page ENDS WRITEBACK rather than being invalidated, which is the
    /// whole difference: the bytes just placed are the node's current bytes,
    /// so dropping them sends the next read of an `fsync`'d or relocated node
    /// back to the medium for what the mount is already holding. Ending the
    /// dirty state instead is what the reference does to a node folio it
    /// writes one at a time, and it needs the layer below to have a way of
    /// being told — which is why this goes through the one-page writeback
    /// entry point rather than placing the block and invalidating behind it.
    /// # C: O(main segments) worst case
    pub(crate) fn writeback_node(&mut self, nid: u32) -> Result<u32, Errno> {
        let cache = Arc::clone(&self.node_cache);
        let mut placed: Result<u32, Errno> = Err(Errno::Enoent);
        let (_, _out) = cache.writeback_nid(nid, &mut |_ino, pages, results| {
            for (i, p) in pages.iter().enumerate() {
                placed = self.writeback_node_block(NodeCache::nid_of(p), p.data);
                // A node released while dirty is reported CLEAN to the page,
                // for the reason the batch path reports it clean: there is
                // nothing to write and nothing a later flush could do with it.
                // The caller still hears the `ENOENT`.
                results[i] = match placed {
                    Ok(_) | Err(Errno::Enoent) => Ok(()),
                    Err(_) => Err(BlockError::Eio),
                };
            }
        });
        placed
    }

    /// Place a batch the mapping handed over, one address per page.
    ///
    /// One slot of `results` per page, arriving prefilled with a failure: a
    /// page this leaves unreported is re-dirtied by the layer below rather
    /// than dropped.
    /// # Ctx: process # Sleeps: y # C: O(pages) blocks
    pub(crate) fn writeback_node_pages(&mut self, pages: &[PageOut<'_>],
                                       results: &mut [KResult<()>], first: &mut Option<Errno>) {
        for (i, p) in pages.iter().enumerate() {
            let nid = NodeCache::nid_of(p);
            results[i] = match self.writeback_node_block(nid, p.data) {
                Ok(_) => Ok(()),
                // A node released while dirty has nothing to write and nothing
                // to report: reporting a failure would leave the page dirty
                // for the next flush to meet again, forever.
                Err(Errno::Enoent) => Ok(()),
                Err(e) => { if first.is_none() { *first = Some(e); } Err(BlockError::Eio) }
            };
        }
    }

    /// Place every node this mount has changed, reporting the first failure.
    ///
    /// Repeated UNTIL THE MAPPING IS CLEAN, because placing a node can dirty
    /// another one: the node table's own accounting is not node state, but the
    /// cleaner and the space accounting reachable from an allocation are.
    ///
    /// It terminates, and the argument is the same one the reference's own
    /// unbounded retry rests on. The reference shuts every writer out before
    /// it starts — the checkpoint holds the whole-filesystem lock and the node
    /// change lock across its retry — so the dirty set can only grow by what
    /// the flush ITSELF dirties. Here that exclusion is the `&mut` on the
    /// mount: nothing else can reach a node while this runs. Each pass claims
    /// every page dirty when it started and either places it or ends the loop
    /// with the error, so the set strictly drains unless placing a node dirties
    /// one that was not dirty — and a placement that did that forever would be
    /// a filesystem that cannot be checkpointed at all, which is a defect to
    /// find rather than a count to survive.
    /// # Ctx: process # Sleeps: y # C: O(dirty nodes)
    pub(crate) fn flush_all_nodes(&mut self) -> Result<(), Errno> {
        let cache = Arc::clone(&self.node_cache);
        drain_nodes(|| cache.dirty(), || {
            let mut first: Option<Errno> = None;
            let (_, out) = cache.flush(usize::MAX, &mut |_ino, pages, results| {
                self.writeback_node_pages(pages, results, &mut first);
            });
            if let (None, Err(_)) = (first, out) { first = Some(Errno::Eio); }
            first
        })
    }

    /// The mapping this mount reads and changes its nodes through. # C: O(1)
    pub fn node_cache(&self) -> Arc<NodeCache> { Arc::clone(&self.node_cache) }

    /// Nodes changed but not yet placed. # C: O(1)
    pub fn dirty_node_pages(&self) -> usize { self.node_cache.dirty() }

    /// Node blocks this mount answered from its own mapping. # C: O(1)
    pub fn node_cache_hits(&self) -> u64 { self.node_cache.hits() }

    /// Node reads this mount had to fetch. # C: O(1)
    pub fn node_cache_misses(&self) -> u64 { self.node_cache.misses() }

    /// Node pages held right now. # C: O(1)
    pub fn node_cached_pages(&self) -> usize { self.node_cache.cached() }

    /// Forget the page held for `nid` — for an id going out of use.
    /// # C: O(1)
    pub(crate) fn forget_node_page(&self, nid: u32) { self.node_cache.forget(nid); }

    /// The block a dirty node holds, if this mount is holding one. # C: O(1)
    pub(crate) fn peek_node(&self, nid: u32) -> Option<Vec<u8>> { self.node_cache.peek(nid) }
}

/// Run `pass` until `dirty` reports nothing left, or until a pass reports.
///
/// The drain's own decision, with the mapping and the placement lifted out, so
/// what it does about a pass that leaves work behind is answerable without a
/// volume: a fixed bound and an unbounded loop are indistinguishable on any
/// workload that converges in one pass, which is every workload this
/// filesystem has.
/// # C: O(passes)
pub(crate) fn drain_nodes<D, P>(mut dirty: D, mut pass: P) -> Result<(), Errno>
where D: FnMut() -> usize, P: FnMut() -> Option<Errno>
{
    while dirty() != 0 {
        if let Some(e) = pass() { return Err(e); }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/nodemap.rs"]
mod tests;
