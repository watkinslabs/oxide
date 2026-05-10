// Anon-VMA reverse mapping per Linux `mm/rmap.c` semantics.
//
// One `AnonVma` per anonymous-VMA family. Every VMA in that family
// (the original + every fork descendant + every COW-split VMA) holds
// an `Arc<AnonVma>`. The AnonVma carries a chain of `RmapTarget`
// edges — one per VMA — so a page-mapped frame can be mapped back
// to every (mm, vma_range) that potentially references it.
//
// Linux design points kept:
// - Lazy AnonVma: created on the first anonymous-VMA insert; cloned
//   into child VMAs at fork time so siblings share one chain.
// - `Weak<AddressSpace>` references: when an AS dies, its targets
//   stay in the chain as dangling weaks, lazily filtered by `walk`.
//   Linux uses anon_vma_chain unlinking; weak-pruning is the same
//   end-state with simpler bookkeeping.
//
// Linux design points NOT yet kept:
// - Hierarchical anon_vma (`anon_vma->root` + parent pointers):
//   a forked child gets its own anon_vma rooted at the parent's, so
//   the parent doesn't enumerate child-only pages on rmap_walk.
//   Our v1 keeps a single flat chain; rmap_walk visits every
//   relative regardless. PTE check at the walk site filters out
//   irrelevant ones.
// - File-backed rmap (`address_space->i_mmap`): TODO once VFS shared
//   mmap lands.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use sync::{AnonVma as AnonVmaClass, Spinlock};

use crate::address_space::AddressSpace;

/// One edge in the AnonVma → VMA chain. `mm` is `Weak` so a dropped
/// AS doesn't keep the rmap alive; `walk` upgrades on visit and
/// silently skips dangling entries.
pub struct RmapTarget {
    pub mm:    Weak<AddressSpace>,
    pub start: u64,
    pub end:   u64,
}

/// Anon-VMA per `mm/rmap.c`. Tracks every VMA that references the
/// anonymous family; stored on each VMA via `Vma::anon_vma`.
pub struct AnonVma {
    chain: Spinlock<Vec<RmapTarget>, AnonVmaClass>,
    /// Stable family id (debug/audit).
    pub id: u64,
}

static ANON_VMA_NEXT_ID: AtomicUsize = AtomicUsize::new(1);

impl AnonVma {
    /// Allocate a fresh anon_vma with no edges. Caller must `attach`
    /// the originating VMA before returning to userspace.
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        let id = ANON_VMA_NEXT_ID.fetch_add(1, Ordering::Relaxed) as u64;
        Arc::new(Self {
            chain: Spinlock::new(Vec::new()),
            id,
        })
    }

    /// Push a new (mm, [start,end)) edge. Idempotent: callers may
    /// re-attach without checking — the walker tolerates duplicates
    /// (rmap_walk hits each VMA's PTE chain anyway), but `detach`
    /// removes only one matching edge per call.
    /// # C: O(1) push
    pub fn attach(&self, mm: Weak<AddressSpace>, start: u64, end: u64) {
        let mut g = self.chain.lock();
        g.push(RmapTarget { mm, start, end });
    }

    /// Remove the first edge matching `(mm, start, end)`. Used by
    /// `munmap` and AS teardown so we don't leak chain entries on
    /// long-lived anon_vmas.
    /// # C: O(N_edges)
    pub fn detach(&self, mm: &Weak<AddressSpace>, start: u64, end: u64) {
        let mm_ptr = mm.as_ptr();
        let mut g = self.chain.lock();
        if let Some(idx) = g.iter().position(|t| {
            t.mm.as_ptr() == mm_ptr && t.start == start && t.end == end
        }) {
            g.swap_remove(idx);
        }
    }

    /// Visit every live target. Drops stale Weak entries lazily.
    /// `f` receives the upgraded `Arc<AddressSpace>` and the VMA range.
    /// # C: O(N_edges)
    pub fn walk<F: FnMut(&Arc<AddressSpace>, u64, u64)>(&self, mut f: F) {
        let g = self.chain.lock();
        for t in g.iter() {
            if let Some(mm) = t.mm.upgrade() {
                f(&mm, t.start, t.end);
            }
        }
    }

    /// Number of currently-live targets (filters dangling weaks).
    /// Hot path for tests + `/proc` accounting.
    /// # C: O(N_edges)
    pub fn live_target_count(&self) -> usize {
        let g = self.chain.lock();
        g.iter().filter(|t| t.mm.upgrade().is_some()).count()
    }

    /// Total chain length including dangling entries. Used by
    /// `gc_dangling` to decide whether a compaction pass is worth it.
    /// # C: O(1)
    pub fn raw_chain_len(&self) -> usize {
        self.chain.lock().len()
    }

    /// Sweep dangling Weak entries out of the chain. Called on
    /// AS teardown so long-lived anon_vmas don't leak slots.
    /// # C: O(N_edges)
    pub fn gc_dangling(&self) {
        let mut g = self.chain.lock();
        g.retain(|t| t.mm.upgrade().is_some());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address_space::AddressSpace;
    use alloc::vec;
    use alloc::vec::Vec;

    fn fresh_as() -> Arc<AddressSpace> {
        AddressSpace::new(0xdead_0000).expect("AS::new for hosted test")
    }

    #[test]
    fn attach_walk_yields_target() {
        let av = AnonVma::new();
        let mm = fresh_as();
        av.attach(Arc::downgrade(&mm), 0x1000, 0x2000);
        let mut hits: Vec<(u64, u64)> = Vec::new();
        av.walk(|_, s, e| hits.push((s, e)));
        assert_eq!(hits, vec![(0x1000, 0x2000)]);
    }

    #[test]
    fn dangling_weak_skipped_by_walk() {
        let av = AnonVma::new();
        {
            let mm = fresh_as();
            av.attach(Arc::downgrade(&mm), 0x4000, 0x5000);
        } // mm Arc dropped here; weak now dangling.
        let mut hits = 0;
        av.walk(|_, _, _| hits += 1);
        assert_eq!(hits, 0);
        assert_eq!(av.live_target_count(), 0);
    }

    #[test]
    fn detach_removes_one_matching_edge() {
        let av = AnonVma::new();
        let mm = fresh_as();
        av.attach(Arc::downgrade(&mm), 0x1000, 0x2000);
        av.attach(Arc::downgrade(&mm), 0x2000, 0x3000);
        av.detach(&Arc::downgrade(&mm), 0x1000, 0x2000);
        assert_eq!(av.live_target_count(), 1);
        let mut starts: Vec<u64> = Vec::new();
        av.walk(|_, s, _| starts.push(s));
        assert_eq!(starts, vec![0x2000]);
    }

    #[test]
    fn fork_chain_two_mms_walked() {
        let av = AnonVma::new();
        let parent = fresh_as();
        let child  = fresh_as();
        av.attach(Arc::downgrade(&parent), 0x10_0000, 0x11_0000);
        av.attach(Arc::downgrade(&child),  0x10_0000, 0x11_0000);
        let mut count = 0;
        av.walk(|_, _, _| count += 1);
        assert_eq!(count, 2);
        assert_eq!(av.live_target_count(), 2);
    }

    #[test]
    fn gc_dangling_compacts() {
        let av = AnonVma::new();
        {
            let dead = fresh_as();
            av.attach(Arc::downgrade(&dead), 0, 0x1000);
        }
        let live = fresh_as();
        av.attach(Arc::downgrade(&live), 0x1000, 0x2000);
        assert_eq!(av.raw_chain_len(), 2);
        av.gc_dangling();
        assert_eq!(av.raw_chain_len(), 1);
    }

    #[test]
    fn unique_id_per_anon_vma() {
        let a = AnonVma::new();
        let b = AnonVma::new();
        assert_ne!(a.id, b.id);
    }
}
