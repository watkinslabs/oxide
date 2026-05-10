// Page-table-side rmap glue per Linux `mm/rmap.c::page_add_anon_rmap`
// + `page_remove_rmap` + `rmap_walk_anon`.
//
// `PageRmap` is the per-PA descriptor a frame allocator (kernel
// `pmm_setup`) parks on each `struct page` analogue. It carries:
// - the `Arc<AnonVma>` family this page belongs to (raw-ptr-stored
//   to avoid kernel-side type plumbing; the encoder/decoder helpers
//   here own the increment/decrement),
// - the mapcount (`# PTEs referencing this frame`).
//
// `rmap_walk_anon` walks the anon_vma chain and yields every (mm,
// vma_range, va) triple a hypothetical mapping has. Caller verifies
// the PTE actually maps this PA before acting (mirrors Linux's
// rmap_walk → try_to_unmap-style filter).
//
// Lifetime safety: `page_add_anon_rmap` calls `Arc::into_raw` to bump
// the strong count; `page_remove_rmap` calls `Arc::from_raw` to drop
// it. The frame's PageRmap thus pins the AnonVma alive for as long
// as any PTE refers to a page in that family.

use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use crate::address_space::AddressSpace;
use crate::anon_vma::AnonVma;

/// Per-frame rmap descriptor. One instance lives next to each
/// `pmm_setup::PageMeta` slot in the kernel (the kernel injects
/// it via `set_rmap_for_pa` at frame construction). VMM keeps
/// these out-of-band so it doesn't depend on PMM internals.
/// # C: O(1)
#[repr(C)]
pub struct PageRmap {
    /// Encoded `Arc<AnonVma>` raw pointer; null = no anon_vma yet.
    /// Manipulated only via `set_anon_vma` / `clear_anon_vma`.
    mapping: AtomicPtr<AnonVma>,
    /// Page index within the anon_vma family — VA / PAGE_SIZE,
    /// taken at the originating page fault. Used by Linux
    /// `vma_address` to compute the VA from a chain target.
    page_index: AtomicU32,
    /// Number of PTEs currently referencing this frame across all
    /// AS in the family. Bumped by `page_add_rmap_pte`, decremented
    /// by `page_remove_rmap_pte`. When it hits zero callers may free
    /// the frame.
    mapcount: AtomicU32,
}

impl PageRmap {
    /// Construct an empty PageRmap. # C: O(1)
    pub const fn new() -> Self {
        Self {
            mapping: AtomicPtr::new(core::ptr::null_mut()),
            page_index: AtomicU32::new(0),
            mapcount: AtomicU32::new(0),
        }
    }

    /// `Linux: page->mapping`. Bumps the AnonVma's strong count and
    /// stores the raw pointer. Idempotent — a re-call on the same
    /// page (e.g. wp-fault → install same anon_vma) drops the
    /// previously-stored Arc to avoid leaking.
    /// # SAFETY: `pa` must be a kernel-owned frame; caller holds the
    /// PT lock for the AS that's installing the mapping.
    /// # C: O(1)
    pub fn set_anon_vma(&self, av: &Arc<AnonVma>, page_index: u32) {
        let raw = Arc::into_raw(Arc::clone(av)) as *mut AnonVma;
        let prev = self.mapping.swap(raw, Ordering::AcqRel);
        if !prev.is_null() {
            // SAFETY: prev was installed by an earlier set_anon_vma
            // call which used Arc::into_raw; we own that strong ref
            // and now drop it via Arc::from_raw.
            unsafe { Arc::from_raw(prev) };
        }
        self.page_index.store(page_index, Ordering::Release);
    }

    /// Clear the anon_vma reference. Called when the frame is
    /// returning to the PMM free pool. Drops the held Arc.
    /// # SAFETY: caller holds exclusive ownership of the frame.
    /// # C: O(1)
    pub fn clear_anon_vma(&self) {
        let prev = self.mapping.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !prev.is_null() {
            // SAFETY: prev was installed by set_anon_vma's into_raw;
            // we now own it and drop the Arc.
            unsafe { Arc::from_raw(prev) };
        }
        self.page_index.store(0, Ordering::Release);
        self.mapcount.store(0, Ordering::Release);
    }

    /// Snapshot the current AnonVma reference. Returns `None` if no
    /// anon_vma is bound. Bumps the strong count on success so the
    /// caller's clone is independent of the page's slot.
    /// # C: O(1)
    pub fn anon_vma(&self) -> Option<Arc<AnonVma>> {
        let raw = self.mapping.load(Ordering::Acquire);
        if raw.is_null() { return None; }
        // SAFETY: raw was installed by set_anon_vma via into_raw;
        // increment_strong_count is sound on a live Arc raw pointer.
        unsafe { Arc::increment_strong_count(raw); }
        // SAFETY: we just bumped the strong count; `Arc::from_raw`
        // converts the raw pointer back to an Arc and we transfer
        // ownership to the caller.
        Some(unsafe { Arc::from_raw(raw) })
    }

    /// Read the page's stored vma offset.
    /// # C: O(1)
    pub fn page_index(&self) -> u32 {
        self.page_index.load(Ordering::Acquire)
    }

    /// Increment the per-page mapcount (one new PTE references this
    /// frame). Returns the new mapcount.
    /// # C: O(1)
    pub fn add_pte(&self) -> u32 {
        self.mapcount.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Decrement the per-page mapcount. Returns the new mapcount.
    /// When zero, the frame has no remaining PTE references and may
    /// be freed (callers consult PMM refcount before actual free).
    /// # C: O(1)
    pub fn remove_pte(&self) -> u32 {
        let prev = self.mapcount.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prev > 0, "PageRmap::remove_pte under-flow");
        prev - 1
    }

    /// Snapshot mapcount without modification.
    /// # C: O(1)
    pub fn mapcount(&self) -> u32 {
        self.mapcount.load(Ordering::Acquire)
    }
}

impl Default for PageRmap {
    fn default() -> Self { Self::new() }
}

/// One yielded entry from `rmap_walk_anon`. Caller checks the PTE
/// at `va` in `mm`'s PT before assuming the page is actually
/// mapped — chain entries can be stale (other AS has unmapped that
/// page locally without dropping the chain edge).
pub struct RmapVisit {
    pub mm:  Arc<AddressSpace>,
    pub va:  u64,
}

/// Walk every (mm, va) pair that COULD reference the page tracked
/// by `rmap`, given its anon_vma family + page_index. Linux's
/// `rmap_walk_anon` shape, minus the i_mmap branch.
///
/// Visitor receives a freshly upgraded `Arc<AddressSpace>` (so the
/// AS is pinned alive for the duration of `f`) and the VA the page
/// would land at within that AS. Returns the number of visits.
/// # C: O(N_chain)
pub fn rmap_walk_anon<F: FnMut(RmapVisit)>(rmap: &PageRmap, mut f: F) -> usize {
    let av = match rmap.anon_vma() {
        Some(a) => a,
        None    => return 0,
    };
    let page_idx = rmap.page_index() as u64;
    let mut visits = 0;
    av.walk(|mm, start, end| {
        // page_index is an offset in PAGES from the originating
        // VMA's start. Each chain target gives a (start, end) range
        // for ITS clone of the family; the same offset applies.
        let va = start + page_idx * 4096;
        if va >= start && va < end {
            f(RmapVisit { mm: Arc::clone(mm), va });
            visits += 1;
        }
    });
    visits
}

/// Thin helper used by `AddressSpace::fork_cow_pages` to attach a
/// child's anon_vma chain edge atomically with the VMA insert. Not
/// strictly needed (callers can call `attach` directly) but pinned
/// here so the inverse `detach_anon_vma_for_munmap` lives next to
/// it — mirrors the Linux `anon_vma_chain_link`/`unlink` pair.
/// # C: O(1)
pub fn attach_anon_vma_for_vma(
    av: &Arc<AnonVma>,
    mm: &Arc<AddressSpace>,
    start: u64,
    end: u64,
) {
    av.attach(Arc::downgrade(mm), start, end);
}

/// Inverse of `attach_anon_vma_for_vma`. Called from `munmap` and
/// AS teardown.
/// # C: O(N_chain)
pub fn detach_anon_vma_for_vma(
    av: &Arc<AnonVma>,
    mm: &Weak<AddressSpace>,
    start: u64,
    end: u64,
) {
    av.detach(mm, start, end);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AddressSpace;
    use alloc::vec::Vec;

    fn fresh_as() -> Arc<AddressSpace> {
        AddressSpace::new(0xfeed_0000).expect("AS::new")
    }

    #[test]
    fn page_rmap_set_and_get_anon_vma() {
        let rmap = PageRmap::new();
        let av = AnonVma::new();
        rmap.set_anon_vma(&av, 7);
        let got = rmap.anon_vma().expect("anon_vma stored");
        assert_eq!(got.id, av.id);
        assert_eq!(rmap.page_index(), 7);
    }

    #[test]
    fn replace_anon_vma_drops_previous_arc() {
        let rmap = PageRmap::new();
        let av1 = AnonVma::new();
        let av2 = AnonVma::new();
        rmap.set_anon_vma(&av1, 0);
        let av1_id = av1.id;
        // Drop the local Arc; rmap should still hold one ref.
        drop(av1);
        // Replace with av2; old Arc should be dropped here. Hard to
        // observe without leak detection, but after we clear there
        // should be no AnonVma on the rmap.
        rmap.set_anon_vma(&av2, 1);
        let got = rmap.anon_vma().expect("av2 stored");
        assert_eq!(got.id, av2.id);
        assert_ne!(got.id, av1_id);
    }

    #[test]
    fn clear_drops_anon_vma() {
        let rmap = PageRmap::new();
        let av = AnonVma::new();
        rmap.set_anon_vma(&av, 0);
        rmap.clear_anon_vma();
        assert!(rmap.anon_vma().is_none());
    }

    #[test]
    fn mapcount_inc_dec() {
        let rmap = PageRmap::new();
        assert_eq!(rmap.mapcount(), 0);
        assert_eq!(rmap.add_pte(), 1);
        assert_eq!(rmap.add_pte(), 2);
        assert_eq!(rmap.remove_pte(), 1);
        assert_eq!(rmap.mapcount(), 1);
        assert_eq!(rmap.remove_pte(), 0);
    }

    #[test]
    fn rmap_walk_yields_one_per_chain_target() {
        let rmap = PageRmap::new();
        let av = AnonVma::new();
        let parent = fresh_as();
        let child  = fresh_as();
        let vma_start: u64 = 0x10_0000;
        let vma_end:   u64 = 0x11_0000;
        av.attach(Arc::downgrade(&parent), vma_start, vma_end);
        av.attach(Arc::downgrade(&child),  vma_start, vma_end);
        rmap.set_anon_vma(&av, 5);   // page at vma+5*4K
        let mut hits: Vec<u64> = Vec::new();
        rmap_walk_anon(&rmap, |v| hits.push(v.va));
        // Both AS get the same VA; both should be visited.
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0], vma_start + 5 * 4096);
        assert_eq!(hits[1], vma_start + 5 * 4096);
    }

    #[test]
    fn rmap_walk_skips_dropped_mm() {
        let rmap = PageRmap::new();
        let av = AnonVma::new();
        let alive = fresh_as();
        {
            let dead = fresh_as();
            av.attach(Arc::downgrade(&dead), 0, 0x1000);
        }
        av.attach(Arc::downgrade(&alive), 0x10_0000, 0x11_0000);
        rmap.set_anon_vma(&av, 0);
        let mut count = 0;
        rmap_walk_anon(&rmap, |_| count += 1);
        assert_eq!(count, 1, "dropped mm should be skipped, only alive visits");
    }

    #[test]
    fn rmap_walk_no_anon_vma_returns_zero() {
        let rmap = PageRmap::new();
        let mut count = 0;
        let r = rmap_walk_anon(&rmap, |_| count += 1);
        assert_eq!(r, 0);
        assert_eq!(count, 0);
    }
}
