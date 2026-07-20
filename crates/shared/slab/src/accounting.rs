//! PMM-page ownership, memcg charge lifetime, and cache-native slab reclaim.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};

use cgroup::{self, MemoryKind};
use hal::{Pfn, PAGE_SIZE_BYTES};
use pmm::{PageBacking, Pmm};
use sync::{CpuLocalSource, IrqGate, PerCpu, Spinlock};

use crate::{Cache, CacheFlags, CacheInner, CacheLayout, Error, Magazine, PFN_NULL, SLAB_ORDER};

/// A cache without `ACCOUNT` has no memcg owner.  Accounted caches must
/// provide one explicit allocation context at construction.
pub(crate) const NO_MEMCG: u64 = cgroup::NO_MEMCG;

impl<T, B: PageBacking, I: IrqGate, S: CpuLocalSource> Cache<T, B, I, S> {
    /// Construct an explicitly memcg-owned cache. `ACCOUNT` charges and
    /// uncharges exactly the PMM pages this cache acquires/releases; caches
    /// without that flag retain `NO_MEMCG`. # C: O(MAX_CPUS)
    pub fn new_with_context(pmm: &'static Pmm<B, I>, name: &'static str, flags: CacheFlags, memcg: u64) -> Self {
        if flags.contains(CacheFlags::ACCOUNT) && memcg == NO_MEMCG {
            panic!("slab accounted cache missing memcg");
        }
        let layout = CacheLayout::for_type::<T>();
        Self {
            pmm, cache_id: crate::NEXT_CACHE_ID.fetch_add(1, Ordering::Relaxed), name, flags, memcg, layout,
            inner: Spinlock::new(CacheInner {
                partial_head: PFN_NULL, drained_head: PFN_NULL, drained_count: 0, total_slabs: 0,
            }),
            magazines: PerCpu::<Magazine<T>, S>::new(), allocated_objs: AtomicU64::new(0),
            _t: PhantomData, _i: PhantomData,
        }
    }

    /// Context retained with this cache's physical page ownership. # C: O(1)
    pub fn memcg(&self) -> u64 { self.memcg }

    pub(crate) fn alloc_slab_page(&self) -> Result<u64, Error> {
        let kind = self.memory_kind();
        if self.flags.contains(CacheFlags::ACCOUNT)
            && !cgroup::try_charge_memory(self.memcg, kind, PAGE_SIZE_BYTES) {
            return Err(Error::NoMem);
        }
        match self.pmm.alloc(SLAB_ORDER) {
            Ok(pfn) => Ok(pfn.0),
            Err(_) => {
                if self.flags.contains(CacheFlags::ACCOUNT) {
                    cgroup::uncharge_memory(self.memcg, kind, PAGE_SIZE_BYTES);
                }
                Err(Error::NoMem)
            }
        }
    }

    pub(crate) fn free_slab_page(&self, pfn: u64) {
        // SAFETY: cache list removal proves this exact PMM page is no longer
        // reachable by an object or a cache list before returning it to buddy.
        unsafe { self.pmm.free(Pfn(pfn), SLAB_ORDER) };
        if self.flags.contains(CacheFlags::ACCOUNT) {
            cgroup::uncharge_memory(self.memcg, self.memory_kind(), PAGE_SIZE_BYTES);
        }
    }

    fn memory_kind(&self) -> MemoryKind {
        if self.flags.contains(CacheFlags::RECLAIM_ACCOUNT) { MemoryKind::SlabReclaimable }
        else { MemoryKind::SlabUnreclaimable }
    }

    /// Release cache-native fully-free pages only.  This is the target of
    /// PMM's slab shrinker dispatch. # C: O(target × MAX_ORDER)
    pub fn release_idle_slabs(&self, target: usize) -> usize {
        let mut released = 0usize;
        while released < target {
            let pfn = {
                let mut g = self.inner.lock_irqsave::<I>();
                if g.drained_head == PFN_NULL { break; }
                let pfn = g.drained_head;
                // SAFETY: drained_head is a cache-owned, fully-free page.
                g.drained_head = unsafe { self.page(pfn).pop_drained_link() };
                g.drained_count -= 1;
                g.total_slabs -= 1;
                pfn
            };
            self.free_slab_page(pfn);
            released += 1;
        }
        released
    }
}
