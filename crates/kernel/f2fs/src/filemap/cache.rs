//! One mount's mapping of its files' data pages: read, write, flush, forget.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use core::cell::Cell;
use core::sync::atomic::{AtomicU64, Ordering};

use syscall::errno::Errno;

use block::pagecache::{PageOut, Sink};
use block::types::{BlockError, InodeId, KResult, PAGE_BYTES};
use block::PageCache;

use crate::uapi::BLKSIZE;

use super::target::{DataHost, Target};

// The mapping is indexed in pages and a file is addressed in blocks, so the
// two units have to be the same one. They are, on every target this builds
// for; an arch where they are not needs a decision about which of the two the
// index counts, not a silent misfiling of every block.
const _: () = assert!(PAGE_BYTES == BLKSIZE);

/// One mount's mapping of its files' data pages.
///
/// Shared rather than owned: the volume reads and writes through it under the
/// mount's lock, and the machine's flusher reaches the same pages from outside
/// that lock. Two copies would be two answers to what a file holds at an
/// offset, so there is one, behind an `Arc`, and its interior counters are
/// atomic so it may be held on both sides.
pub struct Cache {
    pages: PageCache,
    /// Pages this mount served from here rather than from the medium. Never
    /// derivable afterwards — the whole point of the mapping is that the read
    /// left no trace at the device — so it is counted as it happens.
    hits: AtomicU64,
    /// Pages the mapping could not answer and a reader had to fetch.
    misses: AtomicU64,
    /// Where a dirty page goes when the machine, rather than this filesystem,
    /// decides to write it.
    target: Arc<Target>,
}

impl Cache {
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            pages: PageCache::new(),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            target: Target::new(),
        })
    }

    /// Name the mount whose pages these are, so the machine's flusher and
    /// reclaim can place a dirty one. # C: O(1)
    pub fn set_host(&self, host: Weak<dyn DataHost>) { self.target.set_host(host); }

    /// # C: O(1)
    fn key(ino: u32) -> InodeId { InodeId(u64::from(ino)) }

    /// # C: O(1)
    fn off(index: u64) -> u64 { index.wrapping_mul(BLKSIZE as u64) }

    /// Page `index` of file `ino` if the mapping holds it, without fetching.
    ///
    /// What a read consults before it asks the node tree where the block is.
    /// A page dirtied by a buffered write has no address yet — its slot holds
    /// a reservation, which the tree reports as a hole — so a reader that went
    /// to the tree first would answer a write it had just accepted with
    /// zeroes.
    /// # C: O(height)
    pub fn peek(&self, ino: u32, index: u64) -> Option<Vec<u8>> {
        let page = self.pages.lookup(Self::key(ino), Self::off(index))?;
        self.hits.fetch_add(1, Ordering::Relaxed);
        let bytes = page.data.lock().clone();
        Some(bytes)
    }

    /// Whether the mapping holds page `index` of file `ino`, WITHOUT counting
    /// the question as a read.
    ///
    /// Separate from `peek` because readahead asks it about every block of a
    /// window and never takes the bytes: counting those as hits would report a
    /// hit rate for reads nobody made, and the figure exists to say how much
    /// of the reading this mapping answered.
    /// # C: O(height)
    pub fn holds(&self, ino: u32, index: u64) -> bool {
        self.pages.lookup(Self::key(ino), Self::off(index)).is_some()
    }

    /// Page `index` of file `ino`, fetching it with `fetch` on a miss.
    ///
    /// `fetch` runs at most once per miss and its bytes are what the mapping
    /// keeps, so a fetch that fails leaves nothing behind to be served later.
    /// A fetch that returns the wrong length is refused rather than padded:
    /// a short page filed here would answer a later read with zeroes the file
    /// does not have.
    /// # C: O(height) on a hit, O(fetch) on a miss
    pub fn read<F>(&self, ino: u32, index: u64, fetch: F) -> Result<Vec<u8>, Errno>
    where F: FnOnce() -> Result<Vec<u8>, Errno>
    {
        let (key, off) = (Self::key(ino), Self::off(index));
        if let Some(page) = self.pages.lookup(key, off) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(page.data.lock().clone());
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        // The fetch's OWN error has to survive the round trip: the cache
        // speaks one error type and this filesystem speaks another, and
        // folding `ENOKEY` or `EFBIG` into a generic I/O error at the boundary
        // would report a missing key as a broken disk.
        let held: Cell<Option<Errno>> = Cell::new(None);
        let got = self.pages.read_page_with(key, off, || match fetch() {
            Ok(bytes) if bytes.len() == BLKSIZE => Ok(bytes),
            Ok(_) => { held.set(Some(Errno::Eio)); Err(BlockError::Eio) }
            Err(e) => { held.set(Some(e)); Err(BlockError::Eio) }
        });
        match got {
            Ok(page) => Ok(page.data.lock().clone()),
            Err(_) => Err(held.get().unwrap_or(Errno::Eio)),
        }
    }

    /// File `page` as the contents of block `index` of `ino`, DIRTY.
    ///
    /// The whole block, always: a partial write has already been merged into
    /// the block it lands in by the caller, because the mapping stores blocks
    /// and a short one filed here would answer a later read with zeroes.
    ///
    /// The page becomes the only copy of those bytes. The layer below refuses
    /// to evict it and refuses to dirty it at all unless somewhere to put it
    /// is installed first, which is why the target goes in on the same call.
    /// # C: O(height)
    pub fn write(&self, ino: u32, index: u64, page: Vec<u8>) -> Result<(), Errno> {
        if page.len() != BLKSIZE { return Err(Errno::Einval); }
        let (key, off) = (Self::key(ino), Self::off(index));
        self.pages.set_writeback(key, self.target.clone() as Arc<dyn block::pagecache::Writeback>);
        let resident = self.pages.read_page_with(key, off, || Ok(page.clone()))
            .map_err(|_| Errno::Eio)?;
        // Overwritten unconditionally: the fetch above only ran if the page
        // was absent, so a page that was already resident still holds what it
        // held before this write.
        { let mut buf = resident.data.lock(); buf.copy_from_slice(&page); }
        self.pages.mark_dirty(key, off).map_err(|_| Errno::Eio)?;
        Ok(())
    }

    /// Act on the machine's dirty state after a write dirtied pages.
    ///
    /// Called by the writer with the mount's own lock DROPPED: over the limit
    /// this writes back, which enters the target, which takes that lock.
    /// # Ctx: process # Sleeps: y # C: O(pages written)
    pub fn balance(&self, ino: u32) { self.pages.balance_dirty(Self::key(ino)); }

    /// Write back up to `max` of `ino`'s dirty pages through `sink`, reporting
    /// how many landed.
    ///
    /// The sink rather than the installed target, because every caller of this
    /// is already inside the mount — see the target's own note.
    /// # Ctx: process # Sleeps: y # C: O(pages written)
    pub fn flush(&self, ino: u32, max: usize, sink: Sink<'_>) -> (usize, KResult<()>) {
        self.pages.writeback_with(Self::key(ino), max, sink)
    }

    /// Inodes holding a dirty page right now. # C: O(inodes)
    pub fn dirty_inodes(&self) -> Vec<u32> {
        self.pages.dirty_inodes().iter().filter_map(|i| u32::try_from(i.0).ok()).collect()
    }

    /// Dirty pages held for `ino`. # C: O(1)
    pub fn dirty_pages(&self, ino: u32) -> usize { self.pages.dirty_count(Self::key(ino)) }

    /// The file offset a page offered to a sink belongs to. # C: O(1)
    pub fn index_of(page: &PageOut<'_>) -> u64 { page.offset / BLKSIZE as u64 }

    /// Forget page `index` of `ino`, because what the file has at that offset
    /// is no longer what the mapping holds.
    /// # C: O(height)
    pub fn forget(&self, ino: u32, index: u64) {
        let off = Self::off(index);
        self.pages.invalidate_range(Self::key(ino), off, off + BLKSIZE as u64);
    }

    /// Forget every page of `ino` from `first` on — what shortening a file
    /// leaves behind. A page past the new end that survived would answer a
    /// read after the file grew again with the bytes it used to have.
    /// # C: O(pages of this inode)
    pub fn forget_from(&self, ino: u32, first: u64) {
        self.pages.invalidate_range(Self::key(ino), Self::off(first), u64::MAX);
    }

    /// Forget everything held for `ino`.
    ///
    /// For an inode number about to be handed to something else: a page left
    /// behind would answer for whatever file next takes the id.
    /// # C: O(pages of this inode)
    pub fn forget_inode(&self, ino: u32) { self.pages.invalidate(Self::key(ino)); }

    /// Whether page `index` of `ino` is held, WITHOUT copying it out.
    ///
    /// Separate from [`Self::peek`] because the two answer different
    /// questions and cost different amounts: `peek` hands back the bytes and
    /// counts a hit, which is what a read wants; this answers one bit and
    /// counts nothing, which is what a residency query wants. Asking `peek`
    /// would charge a page copy and a hit per byte of an `mincore` walk and
    /// would report reads that never happened.
    /// # C: O(height)
    pub fn held(&self, ino: u32, index: u64) -> bool { self.pages.holds(Self::key(ino), index) }

    /// What `ino` holds in the INCLUSIVE index range, and in what state.
    ///
    /// Only pages that EXIST are visited, so an unbounded range over a sparse
    /// file costs what the file holds rather than what its index space could
    /// address.
    /// # C: O(pages in range)
    pub fn states(&self, ino: u32, lo: u64, hi: u64) -> Vec<block::pagecache::PageState> {
        self.pages.page_states(Self::key(ino), lo, hi)
    }

    /// Drop what can be spared of `ino`'s pages in the INCLUSIVE index range,
    /// reporting how many went.
    ///
    /// A HINT, and the difference from [`Self::forget`] is the whole point: a
    /// page not yet placed is the only copy of a write, so this leaves a dirty
    /// or in-flight page exactly where it is. `forget` is for an offset whose
    /// contents STOPPED being what the mapping holds, where keeping the page
    /// would serve stale bytes; there the drop is not optional.
    /// # C: O(pages in range)
    pub fn try_forget(&self, ino: u32, lo: u64, hi: u64) -> usize {
        self.pages.try_invalidate_range(Self::key(ino), lo, hi)
    }

    /// Pages held right now. # C: O(inodes)
    pub fn pages(&self) -> usize { self.pages.cached_count() }

    /// Reads served from here since the mount. # C: O(1)
    pub fn hits(&self) -> u64 { self.hits.load(Ordering::Relaxed) }

    /// Reads this mapping could not answer since the mount. # C: O(1)
    pub fn misses(&self) -> u64 { self.misses.load(Ordering::Relaxed) }
}
