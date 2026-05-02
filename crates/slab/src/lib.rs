// Slab allocator — cache of fixed-size objects backed by PMM pages.
// Per docs/12 (FROZEN). v1: global-locked Cache<T> with redzone +
// poison + freed-fill hardening. Per-CPU magazines (`12§3.2`) and
// `kmalloc` size-class router (`12§2`) land in P1-05/P1-06 once the
// PerCpu primitive (`06§4`) ships.
//
// Invariants per `12§1`:
//   I1 alignment: returned ptr aligned to max(min(size,64), align_of<T>).
//   I2 no double-free: poison cookie at obj offset 0; checked on free.
//   I3 no UAF: `0xDD`-fill on free; poison cookie also occupies offset 0.
//   I4 cache correctness: cache_id stamped in slab page header; verified on free.
//   I5 (magazine ↔ global consistency): N/A v1; reinstated when magazines land.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering};

use hal::{Pfn, PAGE_SIZE_BYTES};
use pmm::{kassert, Order, PageBacking, Pmm};
use sync::{IrqGate, NoopIrq, Slab as SlabClass, Spinlock};

mod slab_page;

#[cfg(test)]
mod tests;

use slab_page::{SlabPage, NULL_OFF};

/// Slab pages are PMM order 0 (4 KiB) for v1. Larger objects → order 3
/// (32 KiB) per `12§3.1`; not implemented v1, asserts at `Cache::new`.
const SLAB_ORDER: Order = Order(0);
const PAGE: usize = PAGE_SIZE_BYTES as usize;

/// Watermark of cached "all-free" drained slabs kept for fast refill
/// before excess returns to PMM. Tunable; spec `12§3.3` cites "cached
/// few" without a number.
const DRAINED_RESERVE: u32 = 4;

const PFN_NULL: u64 = u64::MAX;

/// Subsystem error per `38`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NoMem,
    Inval,
    DoubleFree,
    Corruption,
    WrongCache,
}

pub type KResult<T> = core::result::Result<T, Error>;

static NEXT_CACHE_ID: AtomicU32 = AtomicU32::new(1);

/// Per-cache fixed parameters computed once at construction.
#[derive(Copy, Clone, Debug)]
pub struct CacheLayout {
    /// Slot size: `max(size_of<T>(), 16)` rounded up to `obj_align`.
    /// 16-byte minimum makes room for the poison cookie + free-list
    /// offset overlay used while the slot is free.
    pub obj_size: u16,
    /// `max(min(size_of<T>(), 64), align_of<T>())` per `12§1`.
    pub obj_align: u16,
    /// Number of object slots per slab page.
    pub nr_objs: u16,
    /// Byte offset of slot 0 from page start (header size + alignment pad).
    pub obj_offset: u16,
}

impl CacheLayout {
    /// Compute layout for `T`. Panics if `T` is too large for one slab page.
    /// # C: O(1) const-foldable arithmetic.
    pub fn for_type<T>() -> Self {
        Self::for_raw(size_of::<T>(), align_of::<T>())
    }

    /// # C: O(1)
    pub fn for_raw(raw_size: usize, raw_align: usize) -> Self {
        // Spec `12§1` I1: align = max(min(size, 64), requested_align).
        let target_align = core::cmp::max(core::cmp::min(raw_size.max(1), 64), raw_align);
        // Min slot 16B for poison(8) + offset(2) + pad(6).
        let min_slot = 16usize.max(raw_size);
        let obj_size = (min_slot + target_align - 1) & !(target_align - 1);
        let obj_align = target_align;
        let header_padded = (slab_page::HEADER_SIZE + obj_align - 1) & !(obj_align - 1);
        assert!(header_padded < PAGE, "obj_align too large for one slab page");
        let usable = PAGE - header_padded;
        let nr_objs = usable / obj_size;
        assert!(nr_objs > 0, "obj_size too large for one slab page");
        assert!(nr_objs <= u16::MAX as usize, "nr_objs overflow u16");
        Self {
            obj_size: obj_size as u16,
            obj_align: obj_align as u16,
            nr_objs: nr_objs as u16,
            obj_offset: header_padded as u16,
        }
    }
}

/// Cache for objects of type `T`. Single-instance per (cache_id) — see
/// `Cache::new`. Backed by `Pmm<B, I>` per `12§2` + `12§10`.
///
/// Generic over `IrqGate` per `06§3.1` — kernel passes the arch gate
/// (`hal_x86_64::X86IrqGate` / `hal_aarch64::ArmIrqGate`); hosted tests
/// use `NoopIrq`. Slab is "reachable from softirq" per `12§4` so the
/// `Slab`-class spinlock MUST take `lock_irqsave` to prevent
/// process-context-vs-IRQ-context deadlock on a single CPU.
pub struct Cache<T, B: PageBacking, I: IrqGate = NoopIrq> {
    pmm: &'static Pmm<B, I>,
    cache_id: u32,
    name: &'static str,
    layout: CacheLayout,
    inner: Spinlock<CacheInner, SlabClass>,
    _t: PhantomData<fn() -> T>,
    _i: PhantomData<fn() -> I>,
}

struct CacheInner {
    /// Doubly-linked list of slabs with ≥1 free obj. Allocations pop
    /// the head's first free obj; if the slab still has ≥1 free obj
    /// it stays at head, else it is removed entirely.
    partial_head: u64,
    /// Cached "all-free" slabs; drained slabs land here until count
    /// exceeds `DRAINED_RESERVE`, at which point excess returns to PMM.
    drained_head: u64,
    drained_count: u32,
    total_slabs: u32,
    allocated_objs: u64,
}

// SAFETY: T is only ever accessed through Cache::alloc/free which
// guard with the SlabClass spinlock; Cache itself never mutates T.
unsafe impl<T: Send, B: PageBacking, I: IrqGate> Send for Cache<T, B, I> {}
// SAFETY: see Send impl.
unsafe impl<T: Send, B: PageBacking, I: IrqGate> Sync for Cache<T, B, I> {}

impl<T, B: PageBacking, I: IrqGate> Cache<T, B, I> {
    /// # C: O(1)
    pub fn new(pmm: &'static Pmm<B, I>, name: &'static str) -> Self {
        let layout = CacheLayout::for_type::<T>();
        Self {
            pmm,
            cache_id: NEXT_CACHE_ID.fetch_add(1, Ordering::Relaxed),
            name,
            layout,
            inner: Spinlock::new(CacheInner {
                partial_head: PFN_NULL,
                drained_head: PFN_NULL,
                drained_count: 0,
                total_slabs: 0,
                allocated_objs: 0,
            }),
            _t: PhantomData,
            _i: PhantomData,
        }
    }

    /// Per-cache layout (debug + tests).
    /// # C: O(1)
    pub fn layout(&self) -> CacheLayout { self.layout }

    /// Cache name passed to `new` (debug + observability).
    /// # C: O(1)
    pub fn name(&self) -> &'static str { self.name }

    /// Cache id assigned at construction (1-monotonic).
    /// # C: O(1)
    pub fn cache_id(&self) -> u32 { self.cache_id }

    /// Number of objects currently allocated from this cache.
    /// # C: O(1)
    pub fn allocated(&self) -> u64 {
        self.inner.lock_irqsave::<I>().allocated_objs
    }

    /// Number of slab pages owned by this cache (partial + drained
    /// reserve + fully-allocated). For tests + observability.
    /// # C: O(1)
    pub fn total_slabs(&self) -> u32 {
        self.inner.lock_irqsave::<I>().total_slabs
    }

    /// Allocate one `T`-sized slot. Returns a typed `NonNull<T>`.
    /// Caller initializes the slot before use.
    /// # C: O(1) amortized
    /// # Lk: SlabClass
    pub fn alloc(&self) -> KResult<NonNull<T>> {
        let mut g = self.inner.lock_irqsave::<I>();
        // Source order: partial → drained → new from PMM.
        let pfn = if g.partial_head != PFN_NULL {
            g.partial_head
        } else if g.drained_head != PFN_NULL {
            // Promote a drained slab to partial.
            let pfn = g.drained_head;
            // SAFETY: pfn was on drained list ⇒ Cache-owned PMM page.
            let next = unsafe { self.page(pfn).pop_drained_link() };
            g.drained_head = next;
            g.drained_count -= 1;
            // SAFETY: pfn just popped, not on any list; install as partial head.
            unsafe { self.page(pfn).set_partial_links(PFN_NULL, PFN_NULL) };
            g.partial_head = pfn;
            pfn
        } else {
            drop(g);
            let pfn = self.pmm.alloc(SLAB_ORDER).map_err(|_| Error::NoMem)?.0;
            // SAFETY: pfn is a fresh PMM-allocated page exclusively owned by us.
            unsafe { self.init_slab_page(pfn) };
            let mut g2 = self.inner.lock_irqsave::<I>();
            g2.total_slabs += 1;
            // SAFETY: pfn freshly initialized, not yet on any list.
            unsafe { self.page(pfn).set_partial_links(g2.partial_head, PFN_NULL) };
            if g2.partial_head != PFN_NULL {
                // SAFETY: prior head still owned by Cache.
                unsafe { self.page(g2.partial_head).set_partial_prev(pfn) };
            }
            g2.partial_head = pfn;
            g = g2;
            pfn
        };

        // SAFETY: pfn is on partial_head ⇒ Cache-owned. pop_free_obj also
        // verifies + clears the poison cookie per `12§1` I3.
        let off = unsafe { self.page(pfn).pop_free_obj(self.layout.obj_size as usize) };
        debug_assert!(off != NULL_OFF);
        // If slab is now fully allocated (no free obj remaining), remove from partial.
        // SAFETY: pfn is on partial_head per the alloc path above; reading free_count from header.
        if unsafe { self.page(pfn).free_count() } == 0 {
            // SAFETY: pfn currently linked at partial_head; unlink_partial preserves invariants.
            unsafe { self.unlink_partial(&mut g, pfn) };
        }

        g.allocated_objs += 1;
        // SAFETY: page is cache-owned; ptr is page+off, in-range.
        let ptr = unsafe { self.pmm.page_ptr(Pfn(pfn)).add(off as usize) } as *mut T;
        // SAFETY: page_ptr+off is non-null page-internal address.
        Ok(unsafe { NonNull::new_unchecked(ptr) })
    }

    /// Free a previously-allocated `T`-sized slot.
    ///
    /// # SAFETY: `p` must have been returned by a prior `alloc()` on
    /// THIS Cache and not yet freed. Double-free is detected via the
    /// poison cookie (I2). UAF after this call is undefined.
    /// # C: O(1) amortized
    /// # Lk: SlabClass
    pub unsafe fn free(&self, p: NonNull<T>) {
        let raw = p.as_ptr() as *mut u8;
        let page_addr = (raw as usize) & !(PAGE - 1);
        let off = (raw as usize) - page_addr;
        kassert!(off >= self.layout.obj_offset as usize, "slab free: pre-header offset");
        let slot_idx = (off - self.layout.obj_offset as usize) / self.layout.obj_size as usize;
        kassert!(slot_idx < self.layout.nr_objs as usize, "slab free: slot out of range");
        kassert!(
            (off - self.layout.obj_offset as usize) % self.layout.obj_size as usize == 0,
            "slab free: slot misaligned"
        );

        // Identify the owning slab via its self-pfn stamp + cache_id
        // stamped in the page header at init time.
        // SAFETY: page_addr is page-aligned (PageBacking::page_ptr
        // contract); slab pages have a header at offset 0 stamped by
        // `SlabPage::init`; we only read the pfn + cache_id fields.
        let header_pfn = unsafe { SlabPage::read_self_pfn_from_addr(page_addr as *const u8) };
        // SAFETY: same justification as above; header is 64 B at offset 0.
        let header_cache_id = unsafe { SlabPage::read_cache_id_from_addr(page_addr as *const u8) };
        kassert!(header_cache_id == self.cache_id, "slab free: wrong cache");

        let mut g = self.inner.lock_irqsave::<I>();
        let pfn = header_pfn;

        let was_full;
        // SAFETY: pfn is the owning slab from the header self-pfn stamp;
        // cache_id check above confirmed cache ownership.
        was_full = unsafe { self.page(pfn).free_count() } == 0;

        // Push obj onto slab freelist; double-free + corruption checks
        // happen inside push_free_obj via the poison cookie.
        // SAFETY: pfn is cache-owned per header check; slot index validated above.
        unsafe { self.page(pfn).push_free_obj(off as u16, self.layout.obj_size as usize) };

        // Fix up list membership.
        if was_full {
            // SAFETY: pfn was off all lists (was_full ⇒ no free obj ⇒
            // unlinked from partial earlier in alloc); installing as
            // partial head now.
            unsafe { self.page(pfn).set_partial_links(g.partial_head, PFN_NULL) };
            if g.partial_head != PFN_NULL {
                // SAFETY: prior head is cache-owned (on partial list).
                unsafe { self.page(g.partial_head).set_partial_prev(pfn) };
            }
            g.partial_head = pfn;
        }

        // SAFETY: pfn is cache-owned per header check above.
        let now_full_free = unsafe { self.page(pfn).free_count() } == self.layout.nr_objs;
        if now_full_free {
            // Drain: pull from partial, push to drained reserve OR PMM.
            // SAFETY: pfn currently on partial — was_full=false implies
            // it was on partial, OR was_full=true inserted it just above.
            unsafe { self.unlink_partial(&mut g, pfn) };
            if g.drained_count < DRAINED_RESERVE {
                // SAFETY: pfn was just unlinked from partial; not on any list now.
                unsafe { self.page(pfn).set_drained_link(g.drained_head) };
                g.drained_head = pfn;
                g.drained_count += 1;
            } else {
                // Return to PMM.
                g.total_slabs -= 1;
                drop(g);
                // SAFETY: pfn was cache-owned; we just severed all
                // links + the slab is fully freed (0 outstanding objs).
                unsafe { self.pmm.free(Pfn(pfn), SLAB_ORDER) };
                let mut g2 = self.inner.lock_irqsave::<I>();
                g2.allocated_objs -= 1;
                return;
            }
        }

        g.allocated_objs -= 1;
    }

    // ----- internal helpers -----

    /// Get a [`SlabPage`] view over the page at `pfn`.
    ///
    /// # SAFETY: caller has verified that `pfn` is a cache-owned slab
    /// page (initialized via `init_slab_page` or popped from one of
    /// our lists).
    unsafe fn page(&self, pfn: u64) -> SlabPage {
        // SAFETY: caller-asserted cache-owned page; `pmm.page_ptr` is
        // safe to call for caller-owned pfns per `pmm::Pmm::page_ptr`.
        let p = unsafe { self.pmm.page_ptr(Pfn(pfn)) };
        SlabPage::from_raw(p)
    }

    /// Initialize a fresh PMM page as a slab for this cache.
    ///
    /// # SAFETY: `pfn` was just returned by `pmm.alloc(SLAB_ORDER)`
    /// and is exclusively owned by this Cache.
    unsafe fn init_slab_page(&self, pfn: u64) {
        // SAFETY: pfn freshly PMM-owned per fn contract.
        let p = unsafe { self.pmm.page_ptr(Pfn(pfn)) };
        // SAFETY: writing into a fresh PMM page; layout constants pre-validated in Cache::new.
        unsafe {
            SlabPage::init(
                p,
                pfn,
                self.cache_id,
                self.layout.obj_size,
                self.layout.obj_align,
                self.layout.nr_objs,
                self.layout.obj_offset,
            )
        };
    }

    /// Remove `pfn` from the partial list. Assumes it's on the list.
    ///
    /// # SAFETY: `pfn` is cache-owned and currently linked into partial.
    unsafe fn unlink_partial(&self, g: &mut CacheInner, pfn: u64) {
        // SAFETY: pfn caller-asserted cache-owned and on partial list per fn contract.
        let (next, prev) = unsafe { self.page(pfn).partial_links() };
        if prev == PFN_NULL {
            g.partial_head = next;
        } else {
            // SAFETY: prev is also cache-owned (on same list).
            unsafe { self.page(prev).set_partial_next(next) };
        }
        if next != PFN_NULL {
            // SAFETY: next is cache-owned (on same list).
            unsafe { self.page(next).set_partial_prev(prev) };
        }
        // SAFETY: pfn now severed; clear stale links to surface bugs.
        unsafe { self.page(pfn).set_partial_links(PFN_NULL, PFN_NULL) };
    }
}

