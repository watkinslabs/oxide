//! One inode's cached pages — the reference's `address_space` (`17§4.1`,
//! `17§5`).
//!
//! Holds the radix tree of resident pages, the per-inode DIRTY list `17§4.3`
//! requires, and the writeback target those dirty pages go to. One spinlock
//! covers all three: a page, its dirty membership and its writeback state
//! change together, and `17§5` puts that lock at per-inode granularity.
//!
//! Nothing that sleeps runs under it — no device I/O, no caller buffer copy —
//! per `06§3.6`; every I/O path snapshots what it needs, drops the lock, and
//! only then submits.

extern crate alloc;
use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};

use sync::{Inode as InodeClass, Spinlock};

use crate::types::{InodeId, KResult, PageFlags};

use super::page::CachedPage;
use super::radix::RadixTree;

/// One page offered to a writeback target: where in the file it belongs and
/// the bytes to put there. The bytes are a snapshot taken out from under the
/// page lock, so a target may hold them across an operation that sleeps.
pub struct PageOut<'a> {
    pub offset: u64,
    pub data:   &'a [u8],
}

/// Where a mapping's dirty pages go when writeback runs — the reference's
/// `a_ops->writepages`. A mapping that has never been written has none, and
/// nothing can dirty a page without installing one, so the flusher never
/// meets a dirty page it cannot place.
///
/// WHOLE-MAPPING, never per page. A filesystem whose page addresses are chosen
/// at writeback — every out-of-place log-structured one — decides where a
/// batch goes as a batch: one allocator visit, one lock acquisition, one
/// ordering. A per-page entry point forces that filesystem to take its own
/// lock once per page from inside a call the cache makes while it is itself
/// dirtying a page, which is where the reference's own per-page writeback
/// entry point ended up and why it no longer has one.
pub trait Writeback: Send + Sync {
    /// Put a batch of one mapping's pages on the medium.
    ///
    /// `results` has one slot per page and arrives prefilled with a failure;
    /// the target overwrites the slot of each page whose bytes it landed. A
    /// page the target never reports is treated as not written and is
    /// re-dirtied, because the alternative — assuming success — drops the only
    /// copy of a write the caller was told had succeeded.
    /// # Ctx: process # Sleeps: y # C: O(I/O)
    fn writepages(&self, ino: InodeId, pages: &[PageOut<'_>], results: &mut [KResult<()>]);
    /// Barrier the medium after a run of pages (`fsync`'s cache flush).
    /// # C: O(I/O)
    fn sync_medium(&self) -> KResult<()>;
}

pub(super) struct MappingState {
    /// Resident pages, keyed by page index (`17§4.1`).
    pub(super) tree:  RadixTree<Arc<CachedPage>>,
    /// This inode's dirty page indexes (`17§4.3` step 3). Invariant 2 of
    /// `17§1`: a dirty page is on exactly one such list.
    pub(super) dirty: BTreeSet<u64>,
    /// Where [`MappingState::dirty`] gets written.
    pub(super) wb:    Option<Arc<dyn Writeback>>,
}

/// One inode's page cache.
pub struct Mapping {
    pub(super) ino: InodeId,
    pub(super) st:  Spinlock<MappingState, InodeClass>,
    /// Already on the global dirty-inode list, so the flusher enqueues it once.
    pub(super) queued: AtomicBool,
    /// When this mapping first went dirty with nothing else pending, for the
    /// flusher's expiry sweep. Nanoseconds on the same clock the flusher reads.
    pub(super) dirtied_when: AtomicU64,
    /// Pages handed to the writeback target and not yet completed.
    pub(super) inflight: AtomicUsize,
}

impl Mapping {
    /// # C: O(1)
    pub(super) fn new(ino: InodeId) -> Arc<Self> {
        Arc::new(Self {
            ino,
            st: Spinlock::new(MappingState { tree: RadixTree::new(), dirty: BTreeSet::new(), wb: None }),
            queued: AtomicBool::new(false),
            dirtied_when: AtomicU64::new(0),
            inflight: AtomicUsize::new(0),
        })
    }

    /// The inode these pages belong to. # C: O(1)
    pub fn ino(&self) -> InodeId { self.ino }

    /// Resident pages. # C: O(1)
    pub fn nrpages(&self) -> usize { self.st.lock().tree.len() }

    /// Dirty pages awaiting writeback. # C: O(1)
    pub fn nr_dirty(&self) -> usize { self.st.lock().dirty.len() }

    /// Install the writeback target if the mapping has none. Never replaces an
    /// installed one: two owners for one mapping's writeback is the split
    /// source of truth that lets a page be written to the wrong place.
    /// # C: O(1)
    pub(super) fn ensure_writeback(&self, wb: &Arc<dyn Writeback>) {
        let mut g = self.st.lock();
        if g.wb.is_none() { g.wb = Some(Arc::clone(wb)); }
    }

    /// The installed writeback target. # C: O(1)
    pub(super) fn writeback_target(&self) -> Option<Arc<dyn Writeback>> {
        self.st.lock().wb.clone()
    }

    /// Whether this mapping has somewhere to put a dirty page. # C: O(1)
    pub(super) fn has_writeback(&self) -> bool { self.st.lock().wb.is_some() }

    /// # C: O(height)
    pub(super) fn get(&self, index: u64) -> Option<Arc<CachedPage>> {
        self.st.lock().tree.get(index).cloned()
    }

    /// Publish `page` at `index` unless something is already there, reporting
    /// what the tree holds afterwards. Checked under the same lock as the
    /// insert, so a race loses cleanly rather than replacing a page another
    /// caller is already waiting on. # C: O(height)
    pub(super) fn insert_unique(&self, index: u64, page: Arc<CachedPage>) -> Result<(), Arc<CachedPage>> {
        let mut g = self.st.lock();
        if let Some(existing) = g.tree.get(index) { return Err(Arc::clone(existing)); }
        g.tree.insert(index, page);
        Ok(())
    }

    /// [`Self::insert_unique`] with a ceiling on how many pages this mapping
    /// may hold, tested under the SAME lock as the insert so a cap is a cap
    /// rather than a race. # C: O(height)
    pub(super) fn insert_unique_capped(&self, index: u64, page: Arc<CachedPage>, cap: usize) -> bool {
        let mut g = self.st.lock();
        if g.tree.len() >= cap { return false; }
        if g.tree.get(index).is_some() { return false; }
        g.tree.insert(index, page);
        true
    }

    /// Drop `index` unless the page there is dirty or busy with I/O. Returns
    /// the page actually removed. A dirty page is NEVER dropped here: `17§4.4`
    /// makes writeback a precondition of eviction, and losing that check loses
    /// the only copy of the bytes. # C: O(height)
    pub(super) fn evict(&self, index: u64) -> Option<Arc<CachedPage>> {
        let mut g = self.st.lock();
        let page = g.tree.get(index)?;
        if page.is_dirty() || page.is_locked() || page.is_writeback() { return None; }
        g.tree.remove(index)
    }

    /// Unconditional removal — truncate/invalidate, where the caller has
    /// decided the bytes are gone. Drops the page's dirty membership with it
    /// so the global count cannot outlive the page. Returns whether the page
    /// removed was dirty. # C: O(height)
    pub(super) fn remove(&self, index: u64) -> Option<bool> {
        let mut g = self.st.lock();
        let page = g.tree.remove(index)?;
        let was_dirty = g.dirty.remove(&index);
        drop(g);
        page.clear_flags(PageFlags::DIRTY);
        Some(was_dirty)
    }

    /// Mark `index` dirty and put it on this inode's dirty list. Reports
    /// whether the page went from clean to dirty, which is what the global
    /// count is stepped by. # C: O(log dirty)
    pub(super) fn set_dirty(&self, index: u64) -> bool {
        let mut g = self.st.lock();
        let Some(page) = g.tree.get(index).cloned() else { return false; };
        let newly = g.dirty.insert(index);
        drop(g);
        page.set_flags(PageFlags::DIRTY);
        newly
    }

    /// Take up to `max` dirty indexes off the list and mark their pages under
    /// writeback, in one step. Between here and completion the page is neither
    /// dirty nor evictable, which is `17§1` invariants 2 and 3.
    /// # C: O(taken)
    pub(super) fn take_for_writeback(&self, max: usize) -> Vec<(u64, Arc<CachedPage>)> {
        let mut g = self.st.lock();
        let idxs: Vec<u64> = g.dirty.iter().take(max).copied().collect();
        let mut out = Vec::with_capacity(idxs.len());
        for idx in idxs {
            let Some(page) = g.tree.get(idx).cloned() else { continue; };
            g.dirty.remove(&idx);
            page.clear_flags(PageFlags::DIRTY);
            page.set_flags(PageFlags::WRITEBACK);
            out.push((idx, page));
        }
        out
    }

    /// [`Self::take_for_writeback`] restricted to the INCLUSIVE index range
    /// `[lo, hi]` — what a range `fsync` or a `sync_file_range` asks for.
    ///
    /// Restricted at the CLAIM rather than filtered afterwards, because the
    /// claim is what takes a page off the dirty list: a batch claimed whole and
    /// then filtered would have marked pages under writeback that nobody is
    /// going to write. Pages outside the range keep their dirty state untouched
    /// and are the next unbounded flush's work.
    /// # C: O(dirty pages of this inode)
    pub(super) fn take_range_for_writeback(&self, lo: u64, hi: u64, max: usize)
        -> Vec<(u64, Arc<CachedPage>)>
    {
        let mut g = self.st.lock();
        let idxs: Vec<u64> = g.dirty.range(lo..=hi).take(max).copied().collect();
        let mut out = Vec::with_capacity(idxs.len());
        for idx in idxs {
            let Some(page) = g.tree.get(idx).cloned() else { continue; };
            g.dirty.remove(&idx);
            page.clear_flags(PageFlags::DIRTY);
            page.set_flags(PageFlags::WRITEBACK);
            out.push((idx, page));
        }
        out
    }

    /// Take ONE named dirty index for writeback — what reclaim needs, which
    /// has chosen a specific cold page rather than "some dirty page".
    /// # C: O(log dirty)
    pub(super) fn take_index_for_writeback(&self, index: u64) -> Option<Arc<CachedPage>> {
        let mut g = self.st.lock();
        let page = g.tree.get(index).cloned()?;
        if !g.dirty.remove(&index) { return None; }
        drop(g);
        page.clear_flags(PageFlags::DIRTY);
        page.set_flags(PageFlags::WRITEBACK);
        Some(page)
    }

    /// Writeback of one page finished. Success clears the writeback state;
    /// failure re-dirties the page, so the bytes stay in the cache and the
    /// next `fsync` reports the error rather than the data disappearing.
    /// Reports whether the page went back onto the dirty list. # C: O(log dirty)
    pub(super) fn end_writeback(&self, index: u64, ok: bool) -> bool {
        let mut g = self.st.lock();
        let Some(page) = g.tree.get(index).cloned() else { return false; };
        page.clear_flags(PageFlags::WRITEBACK);
        if ok { return false; }
        let requeued = g.dirty.insert(index);
        drop(g);
        page.set_flags(PageFlags::DIRTY);
        requeued
    }

    /// Complete resident dirty pages whose bytes were included in a larger
    /// writeback object. The caller holds the inode's filesystem ownership and
    /// has already written the object containing every selected page; no page
    /// is under writeback here, so removing it from the dirty set is the same
    /// atomic state transition as a successful ordinary completion.
    /// # C: O(N selected dirty pages)
    pub(super) fn clean_range(&self, lo: u64, hi: u64) -> usize {
        let mut g = self.st.lock();
        let indexes: Vec<u64> = g.dirty.range(lo..=hi).copied().collect();
        for &index in &indexes {
            g.dirty.remove(&index);
            if let Some(page) = g.tree.get(index) { page.clear_flags(PageFlags::DIRTY); }
        }
        indexes.len()
    }

    /// Indexes of every resident page in `[lo, hi)`. # C: O(pages in range)
    pub(super) fn keys_in_range(&self, lo: u64, hi: u64) -> Vec<u64> {
        self.st.lock().tree.keys_in_range(lo, hi)
    }

    /// Every resident page, ascending. # C: O(pages)
    pub(super) fn pages(&self) -> Vec<(u64, Arc<CachedPage>)> {
        let g = self.st.lock();
        let mut out = Vec::with_capacity(g.tree.len());
        g.tree.for_each(|k, v| out.push((k, Arc::clone(v))));
        out
    }
}
