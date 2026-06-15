// Segregated free-list allocator (docs/59§6 G5). Small requests are
// served from per-size-class free lists carved out of mmap'd slabs;
// large requests (> MAX_CLASS) are mmap'd directly. No coalescing — size
// classes make free O(1) and sidestep boundary-tag merge bugs; freed
// small blocks are retained on their class list (like glibc tcache/bins),
// not returned to the OS. tcache/per-arena scaling is a later perf
// refinement (the impl is complete, not a subset).
//
// Every returned pointer has a 16-byte header in the 16 bytes preceding
// it, so free()/realloc()/usable_size() work uniformly:
//   [tag:usize][info:usize] | payload (16-aligned) ...
// tag = CLASS (info = class index) | MMAP (info = total bytes) |
//       ALIGNED (info = underlying raw payload pointer).
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

const HEADER: usize = 16;
const PAGE: usize = 4096;
const SLAB: usize = 1 << 20; // 1 MiB carving unit for small blocks

const TAG_CLASS: usize = 0;
const TAG_MMAP: usize = 1;
const TAG_ALIGNED: usize = 2;

// All multiples of 16 so payload (slab/page base + HEADER) stays 16-aligned.
const CLASS_SIZES: [usize; 32] = [
    16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512,
    640, 768, 896, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384,
    24576, 32768, 49152, 65536,
];
const MAX_CLASS: usize = 65536;

#[inline]
fn class_index(size: usize) -> usize {
    let mut i = 0;
    while CLASS_SIZES[i] < size { i += 1; }
    i
}
#[inline]
fn round_up(v: usize, a: usize) -> usize { (v + a - 1) & !(a - 1) }

// ---- OS page source (abstracted so the algorithm is oracle-tested) ----
#[cfg(feature = "freestanding")]
unsafe fn os_alloc(len: usize) -> *mut u8 {
    use crate::posix::mman;
    // SAFETY: anonymous private mapping; null addr lets the kernel choose,
    // fd=-1/off=0 per MAP_ANONYMOUS. Returns MAP_FAILED on error.
    let p = unsafe {
        mman::mmap(core::ptr::null_mut(), len, mman::PROT_READ | mman::PROT_WRITE,
                   mman::MAP_PRIVATE | mman::MAP_ANONYMOUS, -1, 0)
    };
    if p == mman::MAP_FAILED { core::ptr::null_mut() } else { p }
}
#[cfg(feature = "freestanding")]
unsafe fn os_free(p: *mut u8, len: usize) {
    // SAFETY: unmaps a region previously returned by os_alloc with the
    // same length; caller guarantees the region is no longer referenced.
    unsafe { crate::posix::mman::munmap(p, len); }
}
#[cfg(all(not(feature = "freestanding"), any(test, feature = "hosted")))]
unsafe fn os_alloc(len: usize) -> *mut u8 {
    // SAFETY: host std allocator stands in for mmap so the free-list
    // algorithm runs under the hosted oracle; layout is page-aligned.
    unsafe { std::alloc::alloc(std::alloc::Layout::from_size_align(len, PAGE).unwrap()) }
}
#[cfg(all(not(feature = "freestanding"), any(test, feature = "hosted")))]
unsafe fn os_free(p: *mut u8, len: usize) {
    // SAFETY: frees a region from os_alloc with the identical layout.
    unsafe { std::alloc::dealloc(p, std::alloc::Layout::from_size_align(len, PAGE).unwrap()); }
}
// Plain workspace rlib build (no freestanding, no std): never runs, but
// must compile since malloc() is always built.
#[cfg(all(not(feature = "freestanding"), not(test), not(feature = "hosted")))]
unsafe fn os_alloc(_len: usize) -> *mut u8 { core::ptr::null_mut() }
#[cfg(all(not(feature = "freestanding"), not(test), not(feature = "hosted")))]
unsafe fn os_free(_p: *mut u8, _len: usize) {}

// ---- header access ----
#[inline]
unsafe fn hdr_write(payload: *mut u8, tag: usize, info: usize) {
    // SAFETY: payload has a 16-byte header immediately before it (two
    // usize slots) reserved by the carve/mmap path.
    unsafe {
        let h = payload.sub(HEADER) as *mut usize;
        *h = tag;
        *h.add(1) = info;
    }
}
#[inline]
unsafe fn hdr_read(payload: *const u8) -> (usize, usize) {
    // SAFETY: payload was returned by this allocator, so its 16-byte
    // header is initialised.
    unsafe {
        let h = payload.sub(HEADER) as *const usize;
        (*h, *h.add(1))
    }
}

// ---- the heap (single global, spinlock-guarded) ----
struct Heap {
    free: [*mut u8; CLASS_SIZES.len()],
    cur: usize,
    end: usize,
}

struct Global {
    lock: AtomicBool,
    heap: UnsafeCell<Heap>,
}
// SAFETY: all access to `heap` is serialised by the `lock` spinlock; raw
// pointers inside are owned by the allocator and never aliased mutably.
unsafe impl Sync for Global {}

static GLOBAL: Global = Global {
    lock: AtomicBool::new(false),
    heap: UnsafeCell::new(Heap { free: [core::ptr::null_mut(); CLASS_SIZES.len()], cur: 0, end: 0 }),
};

impl Global {
    #[inline]
    fn enter(&self) -> *mut Heap {
        while self.lock.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        self.heap.get()
    }
    #[inline]
    fn leave(&self) { self.lock.store(false, Ordering::Release); }
}

// carve `bs+HEADER` bytes from the slab, growing it if needed; returns
// payload or null on OOM. caller holds the lock.
unsafe fn carve(h: *mut Heap, bs: usize) -> *mut u8 {
    // SAFETY: caller holds the spinlock so *h is exclusively ours; we only
    // hand out memory inside the current mmap'd slab.
    unsafe {
        let need = HEADER + bs;
        if (*h).cur + need > (*h).end {
            let slab = if need > SLAB { round_up(need, PAGE) } else { SLAB };
            let p = os_alloc(slab);
            if p.is_null() { return core::ptr::null_mut(); }
            (*h).cur = p as usize;
            (*h).end = p as usize + slab;
        }
        let block = (*h).cur as *mut u8;
        (*h).cur += need;
        block.add(HEADER)
    }
}

pub(crate) unsafe fn malloc(size: usize) -> *mut u8 {
    // SAFETY: pure allocation; returns a fresh 16-aligned region of at
    // least `size` bytes (size 0 → a minimal unique block) or null.
    unsafe {
        let size = if size == 0 { 1 } else { size };
        if size > MAX_CLASS {
            let total = round_up(HEADER + size, PAGE);
            let p = os_alloc(total);
            if p.is_null() { crate::internal::errno::set(12); return core::ptr::null_mut(); }
            hdr_write(p.add(HEADER), TAG_MMAP, total);
            return p.add(HEADER);
        }
        let ci = class_index(size);
        let h = GLOBAL.enter();
        let payload = if !(*h).free[ci].is_null() {
            let p = (*h).free[ci];
            (*h).free[ci] = *(p as *const *mut u8); // pop intrusive next
            p
        } else {
            let p = carve(h, CLASS_SIZES[ci]);
            if !p.is_null() { hdr_write(p, TAG_CLASS, ci); }
            p
        };
        GLOBAL.leave();
        if payload.is_null() { crate::internal::errno::set(12); }
        payload
    }
}

pub(crate) unsafe fn free(ptr: *mut u8) {
    if ptr.is_null() { return; }
    // SAFETY: ptr was returned by this allocator; its header identifies how
    // to release it. Class blocks return to their free list under the lock.
    unsafe {
        let (tag, info) = hdr_read(ptr);
        match tag {
            TAG_MMAP => os_free(ptr.sub(HEADER), info),
            TAG_ALIGNED => free(info as *mut u8),
            _ => {
                let ci = info;
                let h = GLOBAL.enter();
                *(ptr as *mut *mut u8) = (*h).free[ci];
                (*h).free[ci] = ptr;
                GLOBAL.leave();
            }
        }
    }
}

pub(crate) unsafe fn usable_size(ptr: *const u8) -> usize {
    if ptr.is_null() { return 0; }
    // SAFETY: ptr is an allocator-owned pointer with a valid header.
    unsafe {
        let (tag, info) = hdr_read(ptr);
        match tag {
            TAG_MMAP => info - HEADER,
            TAG_ALIGNED => {
                let raw = info as *const u8;
                let base = usable_size(raw);
                base.saturating_sub(ptr as usize - raw as usize)
            }
            _ => CLASS_SIZES[info],
        }
    }
}

pub(crate) unsafe fn calloc(n: usize, sz: usize) -> *mut u8 {
    // SAFETY: zeroed allocation; overflow in n*sz is checked per C calloc.
    unsafe {
        let total = match n.checked_mul(sz) { Some(t) => t, None => { crate::internal::errno::set(12); return core::ptr::null_mut(); } };
        let p = malloc(total);
        if !p.is_null() { core::ptr::write_bytes(p, 0, total); }
        p
    }
}

pub(crate) unsafe fn realloc(ptr: *mut u8, newsize: usize) -> *mut u8 {
    // SAFETY: ptr is null or allocator-owned; grows/shrinks preserving the
    // overlapping prefix, freeing the old block when it moves.
    unsafe {
        if ptr.is_null() { return malloc(newsize); }
        if newsize == 0 { free(ptr); return core::ptr::null_mut(); }
        let old = usable_size(ptr);
        if newsize <= old { return ptr; }
        let np = malloc(newsize);
        if np.is_null() { return core::ptr::null_mut(); }
        core::ptr::copy_nonoverlapping(ptr, np, old.min(newsize));
        free(ptr);
        np
    }
}

pub(crate) unsafe fn aligned(align: usize, size: usize) -> *mut u8 {
    // SAFETY: returns a block aligned to `align` (power of two); the header
    // before the aligned pointer redirects free() to the raw block.
    unsafe {
        if align <= HEADER { return malloc(size); }
        let raw = malloc(size + align + HEADER);
        if raw.is_null() { return core::ptr::null_mut(); }
        let aligned = round_up(raw as usize + HEADER, align) as *mut u8;
        hdr_write(aligned, TAG_ALIGNED, raw as usize);
        aligned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use proptest::prelude::*;

    #[derive(Clone, Debug)]
    enum Op { Alloc(usize), Free(usize), Realloc(usize, usize) }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (1usize..2000).prop_map(Op::Alloc),
            (0usize..40).prop_map(Op::Free),
            (0usize..40, 1usize..4000).prop_map(|(i, s)| Op::Realloc(i, s)),
        ]
    }

    proptest! {
        #[test]
        fn no_overlap_and_data_survives(ops in proptest::collection::vec(op(), 1..300)) {
            // live = (ptr, len, fill)
            let mut live: Vec<(*mut u8, usize, u8)> = Vec::new();
            let mut fill: u8 = 1;
            for o in ops {
                match o {
                    Op::Alloc(sz) => {
                        // SAFETY: sz>0; malloc returns an owned region we fill+track.
                        let p = unsafe { malloc(sz) };
                        prop_assert!(!p.is_null());
                        prop_assert_eq!(p as usize % 16, 0);
                        // SAFETY: p is the live allocation just returned.
                        let us = unsafe { usable_size(p) };
                        prop_assert!(us >= sz);
                        fill = fill.wrapping_add(1).max(1);
                        // SAFETY: p is valid for sz bytes we just allocated.
                        unsafe { core::ptr::write_bytes(p, fill, sz); }
                        live.push((p, sz, fill));
                    }
                    Op::Free(i) => {
                        if !live.is_empty() {
                            let (p, _, _) = live.swap_remove(i % live.len());
                            // SAFETY: p is a live allocation removed from the set.
                            unsafe { free(p); }
                        }
                    }
                    Op::Realloc(i, ns) => {
                        if !live.is_empty() {
                            let idx = i % live.len();
                            let (p, filled, f) = live[idx]; // filled = bytes currently holding f
                            // SAFETY: p is live; realloc preserves min(filled,ns) bytes.
                            let np = unsafe { realloc(p, ns) };
                            prop_assert!(!np.is_null());
                            let keep = filled.min(ns);
                            // SAFETY: np valid for ns bytes; first `keep` carry old fill.
                            let ok = (0..keep).all(|k| unsafe { *np.add(k) } == f);
                            prop_assert!(ok);
                            // re-establish the invariant over the whole new size
                            fill = fill.wrapping_add(1).max(1);
                            // SAFETY: np is valid for the full ns bytes just allocated.
                            unsafe { core::ptr::write_bytes(np, fill, ns); }
                            live[idx] = (np, ns, fill);
                        }
                    }
                }
                // pairwise non-overlap of all live allocations
                for a in 0..live.len() {
                    for b in (a + 1)..live.len() {
                        let (pa, la, _) = live[a];
                        let (pb, lb, _) = live[b];
                        let (sa, sb) = (pa as usize, pb as usize);
                        prop_assert!(sa + la <= sb || sb + lb <= sa, "overlap");
                    }
                }
            }
            // SAFETY: each remaining p is a distinct live allocation we own.
            for (p, _, _) in live { unsafe { free(p); } }
        }
    }
}
