//! One mount's mapping of its NODE blocks, keyed by node id.
//!
//! Keyed by NID, not by block address, which is the key the reference files a
//! node folio under and the only key that survives the node's own movement: a
//! node block is rewritten out of place on every change and relocated by the
//! cleaner, so an address-keyed mapping would have to be invalidated on every
//! move of bytes that did not change, and would answer a lookup of the new
//! address with nothing while holding the identical bytes under the old one.
//! A nid names the node for as long as the node exists.
//!
//! Filed under the volume's own NODE inode number, which the format reserves
//! and no file can take — the same place the reference puts this mapping, and
//! the same shape the metadata mapping already uses for the metadata inode.
//!
//! A page here may be DIRTY, and that is the point of the mapping. A node is
//! changed WHERE IT IS CHANGED and left here; the segment, the log and the
//! block address are chosen later, once, when the page is written back. Until
//! then this page is the only copy of the node, which is why every node read
//! consults this mapping before it consults the node table, and why the table
//! records the node as present-without-an-address until the write lands.
//!
//! COHERENT BY CONSTRUCTION. Every writer of a node block in this filesystem
//! goes through the one node writer, which files its result here, so a page
//! held here is never behind the medium. The one event that invalidates is a
//! node id going out of use: the id can be handed out again, and a page left
//! behind would answer for whatever node next takes it.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use core::sync::atomic::{AtomicU64, Ordering};

use syscall::errno::Errno;

use block::pagecache::{PageOut, Sink, Writeback};
use block::types::{BlockError, InodeId, KResult, PAGE_BYTES};
use block::PageCache;

use sync::{Spinlock, Superblock};

use crate::uapi::BLKSIZE;

// A node block is one page and the mapping is indexed in pages, so the two
// units have to be the same one. They are on every target this builds for.
const _: () = assert!(PAGE_BYTES == BLKSIZE);

/// The mount a node mapping's pages belong to, as much of it as writeback
/// needs.
///
/// Separate from the data mapping's way back because the work is different:
/// a data page is placed against a file's node tree, a node page is placed
/// against the node table. Both are reached from outside this filesystem
/// holding none of its state, which is why either needs one at all.
pub trait NodeHost: Send + Sync {
    /// Put this batch of node pages on the medium, choosing an address for
    /// each. One slot of `results` per page, prefilled with a failure.
    /// # Ctx: process # Sleeps: y # C: O(pages)
    fn writeback_nodes(&self, pages: &[PageOut<'_>], results: &mut [KResult<()>]);
    /// Barrier every device the volume spans. # C: O(devices)
    fn sync_node_medium(&self) -> KResult<()>;
}

/// Where a dirty node page goes when the MACHINE's flusher or reclaim reaches
/// it, as opposed to this filesystem's own flush points.
///
/// The way back is WEAK, for the reason the data mapping's is: a mount that
/// has gone away must not be kept alive by a page still on a reclaim list, and
/// a page whose mount is gone has nowhere to be put — reported as a failed
/// write, so the page stays dirty rather than being dropped with the caller
/// believing it landed.
pub struct NodeTarget {
    host: Spinlock<Option<Weak<dyn NodeHost>>, Superblock>,
}

impl NodeTarget {
    /// # C: O(1)
    pub fn new() -> Arc<Self> { Arc::new(Self { host: Spinlock::new(None) }) }

    /// Name the mount these pages belong to. Separate from construction
    /// because the mapping exists before the mount does. # C: O(1)
    pub fn set_host(&self, host: Weak<dyn NodeHost>) { *self.host.lock() = Some(host); }

    /// # C: O(1)
    fn host(&self) -> Option<Arc<dyn NodeHost>> { self.host.lock().as_ref()?.upgrade() }
}

impl Writeback for NodeTarget {
    /// # Ctx: process # Sleeps: y # C: O(pages)
    fn writepages(&self, _ino: InodeId, pages: &[PageOut<'_>], results: &mut [KResult<()>]) {
        // The slots arrive prefilled with a failure, so leaving them is what
        // re-dirties every page: the bytes stay here and this filesystem's own
        // flush point still has them to write.
        let Some(host) = self.host() else { return; };
        host.writeback_nodes(pages, results);
    }

    /// # C: O(devices)
    fn sync_medium(&self) -> KResult<()> {
        match self.host() { Some(h) => h.sync_node_medium(), None => Err(BlockError::Eio) }
    }
}

/// One mount's mapping of its node blocks.
///
/// Shared rather than owned, for the reason the data mapping is: the volume
/// reads and writes through it under the mount's lock, and the machine's
/// flusher reaches the same pages from outside that lock.
pub struct NodeCache {
    pages: PageCache,
    ino: InodeId,
    /// Node reads served from here rather than from the medium. Never
    /// derivable afterwards, so counted as it happens.
    hits: AtomicU64,
    /// Node reads the mapping could not answer.
    misses: AtomicU64,
    target: Arc<NodeTarget>,
}

impl NodeCache {
    /// # C: O(1)
    pub fn new(node_ino: u32) -> Arc<Self> {
        Arc::new(Self {
            pages: PageCache::new(),
            ino: InodeId(u64::from(node_ino)),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            target: NodeTarget::new(),
        })
    }

    /// Name the mount whose nodes these are. # C: O(1)
    pub fn set_host(&self, host: Weak<dyn NodeHost>) { self.target.set_host(host); }

    /// # C: O(1)
    fn off(nid: u32) -> u64 { u64::from(nid) * BLKSIZE as u64 }

    /// The node id a page offered to a sink belongs to. # C: O(1)
    pub fn nid_of(page: &PageOut<'_>) -> u32 { (page.offset / BLKSIZE as u64) as u32 }

    /// The node block held for `nid`, if any.
    ///
    /// What a node read consults before it asks the node table where the block
    /// is. A node dirtied and not yet placed has no address — the table
    /// reports it as present-without-one — so a reader that went to the table
    /// first would answer with the node's PREVIOUS contents, or with nothing
    /// at all for a node created since the last write.
    /// # C: O(height)
    pub fn peek(&self, nid: u32) -> Option<Vec<u8>> {
        let page = self.pages.lookup(self.ino, Self::off(nid))?;
        self.hits.fetch_add(1, Ordering::Relaxed);
        let bytes = page.data.lock().clone();
        Some(bytes)
    }

    /// Count a read this mapping could not answer. # C: O(1)
    pub fn miss(&self) { self.misses.fetch_add(1, Ordering::Relaxed); }

    /// File `block` as the contents of `nid`, DIRTY.
    ///
    /// The page becomes the only copy of the node. The layer below refuses to
    /// dirty it at all unless somewhere to put it is installed first, which is
    /// why the target goes in on the same call.
    /// # C: O(height)
    pub fn store(&self, nid: u32, block: Vec<u8>) -> Result<(), Errno> {
        if block.len() != BLKSIZE { return Err(Errno::Einval); }
        let off = Self::off(nid);
        self.pages.set_writeback(self.ino, self.target.clone() as Arc<dyn Writeback>);
        let resident = self.pages.read_page_with(self.ino, off, || Ok(block.clone()))
            .map_err(|_| Errno::Eio)?;
        // Overwritten unconditionally: the fetch above only ran if the page
        // was absent, so a page that was already resident still holds what it
        // held before this write.
        { let mut buf = resident.data.lock(); buf.copy_from_slice(&block); }
        self.pages.mark_dirty(self.ino, off).map_err(|_| Errno::Eio)?;
        Ok(())
    }

    /// File `block` as the contents of `nid`, CLEAN — what a read of a node
    /// off the medium leaves behind. # C: O(height)
    pub fn fill(&self, nid: u32, block: Vec<u8>) {
        if block.len() != BLKSIZE { return; }
        let _ = self.pages.read_page_with(self.ino, Self::off(nid), || Ok(block));
    }

    /// Forget the page held for `nid`.
    ///
    /// For a node id going out of use, and for a node this mount has just
    /// placed on the medium by itself rather than through the layer below.
    /// # C: O(height)
    pub fn forget(&self, nid: u32) {
        let off = Self::off(nid);
        self.pages.invalidate_range(self.ino, off, off + BLKSIZE as u64);
    }

    /// Write back up to `max` dirty node pages through `sink`, reporting how
    /// many landed. # Ctx: process # Sleeps: y # C: O(pages written)
    pub fn flush(&self, max: usize, sink: Sink<'_>) -> (usize, KResult<()>) {
        self.pages.writeback_with(self.ino, max, sink)
    }

    /// Act on the machine's dirty state after node pages were dirtied.
    /// # Ctx: process # Sleeps: y # C: O(pages written)
    pub fn balance(&self) { self.pages.balance_dirty(self.ino); }

    /// Nodes changed but not yet placed. # C: O(1)
    pub fn dirty(&self) -> usize { self.pages.dirty_count(self.ino) }

    /// Node pages held right now. # C: O(inodes)
    pub fn cached(&self) -> usize { self.pages.cached_count() }

    /// Node reads served from here since the mount. # C: O(1)
    pub fn hits(&self) -> u64 { self.hits.load(Ordering::Relaxed) }

    /// Node reads this mapping could not answer since the mount. # C: O(1)
    pub fn misses(&self) -> u64 { self.misses.load(Ordering::Relaxed) }
}
