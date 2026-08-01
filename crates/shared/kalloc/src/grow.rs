// Heap growth + `kmalloc` slab refill — the two paths that reach past the
// per-class free lists into the sorted hole list and, when that is exhausted,
// into the PMM. Split out of `lib.rs` so the `GlobalAlloc` surface there stays
// the dispatch manifest it is meant to be (`docs/08§7`).

use core::alloc::Layout;
use core::ptr;
use core::sync::atomic::Ordering;

use crate::sizeclass;
use crate::limits::{GROW_CHUNK_MIN, GROW_HOOK_NONE, NO_MEMCG_CONTEXT};
use crate::state::{AllocState, KAlloc};
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
use crate::caller;
#[cfg(feature = "debug-heappoison")]
use crate::poison;
#[cfg(feature = "debug-dealloc-diag")]
use crate::recent::record_recent_op;

/// T16 (F247) growable kernel heap: when the hole-list allocator can't
/// satisfy a request, fall back to a registered grow callback that
/// asks the PMM for more pages and feeds them to the hole list.
/// Linux's vmalloc equivalent; without it the kernel OOMs on any
/// single workload bigger than the static heap can hold.
///
/// Callback signature: takes the minimum extra bytes needed; returns
/// `(start_addr, size_bytes)` of a fresh region added to the hole
/// list, or `None` if no more memory is available. The callback owns
/// the lifetime of the region — it must stay valid until process
/// shutdown.
pub type GrowFn = fn(min_extra: usize, memcg: u64) -> Option<(usize, usize)>;

impl KAlloc {
    /// Register a callback the alloc path invokes when the hole-list
    /// can't satisfy a request. Idempotent: a later call replaces the
    /// prior hook.
    /// # SAFETY: `f` must remain a valid fn-pointer for the lifetime
    /// of this allocator; the kernel never unloads it.
    /// # C: O(1)
    pub fn set_grow_hook(&self, f: GrowFn) {
        let raw = (f as usize) as u64;
        self.grow_hook.store(raw, Ordering::Release);
    }

    /// Hole-list miss path: ask the PMM grow hook for a fresh region, register
    /// it, then carve `carve_layout` out of it. Split out of `alloc` so the
    /// size-class refill reaches the same growth machinery instead of carrying
    /// a second copy of it.
    /// # SAFETY: same contract as `GlobalAlloc::alloc`; the caller holds the
    /// IRQ guard and must not hold the heap lock.
    /// # C: O(N) plus the grow hook
    pub(crate) unsafe fn grow_and_alloc(&self, layout: Layout, carve_layout: Layout) -> *mut u8 {
        let _ = &layout;
        let raw = self.grow_hook.load(Ordering::Acquire);
        if raw == GROW_HOOK_NONE {
            #[cfg(feature = "debug-heappoison")]
            klog::write_primary_raw(b"[KALLOC] growth-unavailable no-hook\n");
            return self.shrink_classes_and_alloc(carve_layout);
        }
        let memcg = self.active_memcg();
        if memcg == NO_MEMCG_CONTEXT && self.context_required.load(Ordering::Acquire) {
            #[cfg(feature = "debug-heappoison")]
            klog::write_primary_raw(b"[KALLOC] growth-unavailable no-context\n");
            return self.shrink_classes_and_alloc(carve_layout);
        }
        // SAFETY: stored only via set_grow_hook from a `GrowFn`; the
        // round-trip cast restores the fn-pointer's ABI.
        let f: GrowFn = unsafe { core::mem::transmute(raw as usize) };
        // Ask for at least the layout, with align headroom, rounded up
        // to GROW_CHUNK_MIN so we don't thrash the PMM with tiny grows.
        let need = carve_layout.size().saturating_add(carve_layout.align()).max(GROW_CHUNK_MIN);
        #[cfg(feature = "debug-heappoison")]
        {
            klog::write_primary_raw(b"[KALLOC] growth-request bytes=");
            klog::write_primary_dec_u64(need as u64);
            klog::write_primary_raw(b"\n");
        }
        let (addr, size) = match f(need, memcg) {
            Some(p) => {
                #[cfg(feature = "debug-heappoison")]
                {
                    klog::write_primary_raw(b"[KALLOC] growth-acquired addr=");
                    klog::write_primary_hex_u64(p.0 as u64);
                    klog::write_primary_raw(b" bytes=");
                    klog::write_primary_dec_u64(p.1 as u64);
                    klog::write_primary_raw(b"\n");
                }
                p
            }
            None    => {
                #[cfg(feature = "debug-heappoison")]
                klog::write_primary_raw(b"[KALLOC] growth-failed\n");
                return self.shrink_classes_and_alloc(carve_layout);
            }
        };
        let mut g = self.inner.lock();
        #[cfg(feature = "debug-heappoison")]
        g.holes.dump(256);
        // SAFETY: caller of the GrowFn (the kernel boot path) guarantees
        // exclusive ownership of [addr, addr + size); fully writable.
        let registered = unsafe { g.holes.add_region(addr, size) };
        let p = if registered.is_ok() { g.holes.alloc(carve_layout).map_or(ptr::null_mut(), |p| p.as_ptr()) } else { ptr::null_mut() };
        #[cfg(feature = "debug-dealloc-diag")]
        if !p.is_null() { g.size_track.record(p as usize, carve_layout.size()); }
        #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
        if !p.is_null() { g.holes.record_alloc_ip(p as usize, caller::alloc_return_ip()); }
        #[cfg(feature = "debug-dealloc-diag")]
        if !p.is_null() { record_recent_op(caller::alloc_return_ip(), p as usize, true); }
        drop(g);
        if let Err(_e) = registered {
            #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
            {
                klog::write_primary_raw(b"[KALLOC] growth-register-failed addr=");
                klog::write_primary_hex_u64(addr as u64);
                klog::write_primary_raw(b" size=");
                klog::write_primary_dec_u64(size as u64);
                klog::write_primary_raw(b" tag=");
                klog::write_primary_raw(_e.tag());
                klog::write_primary_raw(b"\n");
            }
            assert!(false, "kalloc grow region invalid");
        }
        #[cfg(feature = "debug-heappoison")]
        if !p.is_null() {
            // SAFETY: `p` was just carved with `carve_layout`'s extra
            // trailing bytes reserved exactly for this redzone.
            unsafe { poison::arm_redzone(p, layout); }
        }
        // B1347: validate right after a GROW carve — the large zram allocation
        // grows the heap, and a carve/region-boundary bug would first appear here.
        #[cfg(feature = "debug-dealloc-diag")]
        if !p.is_null() { self.periodic_validate_diag(caller::alloc_return_ip()); }
        #[cfg(feature = "debug-heappoison")]
        klog::write_primary_raw(b"[KALLOC] growth-registered\n");
        // A fresh region that still cannot serve the carve means the heap is
        // fragmented past this request; the size classes are the only reserve
        // left before OOM.
        if p.is_null() { return self.shrink_classes_and_alloc(carve_layout); }
        p
    }

    /// LAST RESORT after growth is unavailable or refused: give the size classes
    /// idle objects back to the hole list, coalesce, and retry. Linux reclaims
    /// slab only under real memory pressure (`do_shrink_slab`), never on the
    /// ordinary allocation path — draining eagerly would re-lengthen the very
    /// free list the classes exist to keep short.
    /// # C: O(F × N) in freed objects F and holes N
    fn shrink_classes_and_alloc(&self, carve_layout: Layout) -> *mut u8 {
        let mut g = self.inner.lock();
        if !Self::drain_classes(&mut g) { return ptr::null_mut(); }
        match g.holes.alloc(carve_layout) {
            Some(p) => {
                #[cfg(feature = "debug-dealloc-diag")]
                g.size_track.record(p.as_ptr() as usize, carve_layout.size());
                p.as_ptr()
            }
            None => ptr::null_mut(),
        }
    }

    /// Return every free object held by the size classes to the hole list, so
    /// coalescing can rebuild the large contiguous holes a big request needs.
    /// Linux does the equivalent under memory pressure (`kmem_cache_shrink`,
    /// `discard_slab`); without it a cache that once served many small objects
    /// would pin that memory against every other size forever.
    /// Returns true if anything moved.
    /// # C: O(F × N) in freed objects F and holes N — a pressure path only
    pub(crate) fn drain_classes(g: &mut AllocState) -> bool {
        let mut moved = false;
        for i in 0..sizeclass::CLASS_SIZES.len() {
            let obj = sizeclass::CLASS_SIZES[i];
            let mut p = g.classes.take_list(i);
            while !p.is_null() {
                // SAFETY: `p` is a detached free object of class `i`; its
                // successor link must be read before the hole list overwrites it.
                let next = unsafe { sizeclass::SizeClasses::next_of(p) };
                // SAFETY: `[p, p+obj)` was carved from this allocator's own slab
                // for class `i` and currently holds no live object.
                let _ = unsafe { g.holes.add_free_region(p as usize, obj) };
                moved = true;
                p = next;
            }
        }
        moved
    }

    /// Carve one slab for class `i` and thread its objects onto that class's
    /// free list, then hand back the first object. Linux `new_slab()` /
    /// `allocate_slab()`. Falls back through smaller carves so a fragmented
    /// heap still serves the request instead of reporting OOM.
    /// # SAFETY: caller holds the IRQ guard and no heap lock; only
    /// allocator-owned memory is threaded onto the class.
    /// # C: O(N) once, amortised over `SLAB_BYTES / obj` allocations
    pub(crate) unsafe fn refill_class(&self, i: usize) -> Option<ptr::NonNull<u8>> {
        let obj = sizeclass::CLASS_SIZES[i];
        for &want in sizeclass::SLAB_FALLBACK_BYTES.iter() {
            let bytes = want.max(obj) / obj * obj;
            let Ok(l) = Layout::from_size_align(bytes, sizeclass::SLAB_ALIGN) else { continue };
            let mut g = self.inner.lock();
            let base = match g.holes.alloc(l) {
                Some(p) => p.as_ptr(),
                None => {
                    drop(g);
                    // SAFETY: `l` is a well-formed carve request; the grow path
                    // registers the new region before allocating from it.
                    let p = unsafe { self.grow_and_alloc(l, l) };
                    if p.is_null() { continue; }
                    g = self.inner.lock();
                    p
                }
            };
            // SAFETY: `base` is a live, exclusively owned, `SLAB_ALIGN`-aligned
            // carve of exactly `bytes` usable bytes, which is `bytes/obj` whole
            // objects of class `i`.
            unsafe { g.classes.push_slab(i, base, bytes / obj) };
            return g.classes.pop(i);
        }
        None
    }
}
