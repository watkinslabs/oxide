// Hosted unit tests: each test instantiates a fresh `KAlloc` over its
// own `Vec<u8>` buffer, exercises `GlobalAlloc`, and verifies pointer
// alignment, reuse after free, OOM, and coalescing.

use super::*;
use core::alloc::Layout;
use core::sync::atomic::{AtomicU64, Ordering};
use std::boxed::Box;
use std::vec;
use std::vec::Vec;

const TEST_REGION_BYTES: usize = 4096;
const TEST_OUTSIDE_LINK_DISTANCE: usize = TEST_REGION_BYTES + MIN_HOLE_ALIGN;
const TEST_SPLIT_ALLOCATION_BYTES: usize = 128;
#[cfg(feature = "debug-heappoison")]
const QUARANTINE_TEST_REGION_BYTES: usize = 512 * 1024;
#[cfg(feature = "debug-heappoison")]
const QUARANTINE_TEST_LAYOUT_BYTES: usize = 64;

/// Allocate `size` bytes of u8-aligned scratch space, returning the
/// raw start address. Pointer is into the test's own heap-allocated
/// `Vec<u8>` and lives for the scope of the test.
fn fresh_heap(size: usize) -> (Box<[u8]>, KAlloc) {
    let buf: Vec<u8> = vec![0u8; size];
    let mut buf = buf.into_boxed_slice();
    let ka = KAlloc::new();
    let start = buf.as_mut_ptr() as usize;
    // SAFETY: we own `buf` for the lifetime of the test; nothing else
    // will read or write the region until `KAlloc` is dropped here.
    unsafe { ka.init(start, size) };
    (buf, ka)
}

fn layout(size: usize, align: usize) -> Layout {
    Layout::from_size_align(size, align).unwrap()
}

#[test]
fn overlapping_free_region_is_rejected_before_header_write() {
    let mut buf: Box<[u8]> = vec![0u8; 4096].into_boxed_slice();
    let start = buf.as_mut_ptr() as usize;
    let size = buf.len();
    let mut holes = HoleList::new();
    // SAFETY: the test owns the whole buffer and installs it once.
    assert!(unsafe { holes.add_region(start, size) }.is_ok());
    let allocation = layout(TEST_SPLIT_ALLOCATION_BYTES, MIN_HOLE_ALIGN);
    let ptr = holes.alloc(allocation).expect("allocation from registered region");
    // SAFETY: first release returns this allocation to the registered region.
    assert!(unsafe { holes.dealloc(ptr, allocation) }.is_ok());
    // SAFETY: this repeats the same owned range solely to validate rejection.
    assert_eq!(unsafe { holes.dealloc(ptr, allocation) }, Err(HoleListError::OverlappingFree));
}

#[test]
fn malformed_successor_link_is_rejected_before_merge_dereference() {
    let mut buf: Box<[u8]> = vec![0u8; TEST_REGION_BYTES].into_boxed_slice();
    let start = buf.as_mut_ptr() as usize;
    let mut holes = HoleList::new();
    // SAFETY: the test owns the complete backing buffer and reserves its prefix.
    assert!(unsafe { holes.add_region(start, TEST_REGION_BYTES) }.is_ok());
    let split = layout(TEST_SPLIT_ALLOCATION_BYTES, MIN_HOLE_ALIGN);
    let first = holes.alloc(split).expect("first isolated allocation");
    let held = holes.alloc(split).expect("middle isolated allocation");
    // SAFETY: `first` came from this list and leaves a free predecessor while
    // `held` keeps the later tail disjoint.
    assert!(unsafe { holes.dealloc(first, split) }.is_ok());
    let later = held.as_ptr() as usize + TEST_SPLIT_ALLOCATION_BYTES;
    let later_hdr = later as *mut crate::holes::HoleHdr;
    let invalid = (start + TEST_OUTSIDE_LINK_DISTANCE) as *mut crate::holes::HoleHdr;
    // SAFETY: this test deliberately corrupts the in-band successor link to
    // prove that the following merge rejects it without dereferencing it.
    unsafe { (*later_hdr).next = Some(core::ptr::NonNull::new_unchecked(invalid)); }
    // SAFETY: releasing the middle allocation makes `try_merge` traverse the
    // corrupted successor link installed above.
    assert_eq!(unsafe { holes.dealloc(held, split) }, Err(HoleListError::OutsideOwnedRegion));
}

// `debug-heappoison`'s redzone check (B1313) runs before the ownership check
// below and catches a duplicate free earlier, with a different panic message
// — split by feature so each build's actual first-line-of-defense is tested.
#[cfg(not(feature = "debug-heappoison"))]
#[test]
#[should_panic(expected = "kalloc")]
fn duplicate_global_free_is_rejected_without_free_list_mutation() {
    let (_buf, ka) = fresh_heap(64 * 1024);
    let l = layout(256, 16);
    // SAFETY: valid layout and initialized allocator.
    let ptr = unsafe { ka.alloc(l) };
    // SAFETY: this is the first release of the allocation above.
    unsafe { ka.dealloc(ptr, l) };
    // SAFETY: intentional duplicate free validates the allocator's ownership
    // check; the test expects the explicit rejection rather than corruption.
    unsafe { ka.dealloc(ptr, l) };
}

#[cfg(feature = "debug-heappoison")]
#[test]
#[should_panic(expected = "heap redzone corrupted")]
fn duplicate_global_free_is_rejected_without_free_list_mutation() {
    let (_buf, ka) = fresh_heap(64 * 1024);
    let l = layout(256, 16);
    // SAFETY: valid layout and initialized allocator.
    let ptr = unsafe { ka.alloc(l) };
    // SAFETY: this is the first release of the allocation above.
    unsafe { ka.dealloc(ptr, l) };
    // SAFETY: intentional duplicate free; the redzone check now catches this
    // before the ownership check gets a chance to run.
    unsafe { ka.dealloc(ptr, l) };
}

#[test]
fn init_then_alloc_returns_aligned() {
    let (_buf, ka) = fresh_heap(64 * 1024);
    let l = layout(128, 64);
    // SAFETY: layout valid; ka initialized.
    let p = unsafe { ka.alloc(l) };
    assert!(!p.is_null());
    assert_eq!(p as usize % 64, 0);
    // SAFETY: just allocated above with the same layout.
    unsafe { ka.dealloc(p, l) };
}

#[test]
fn alloc_before_init_returns_null() {
    let ka = KAlloc::new();
    let l = layout(16, 8);
    // SAFETY: layout valid; ka uninitialized so returns null.
    let p = unsafe { ka.alloc(l) };
    assert!(p.is_null());
}

#[test]
fn dealloc_then_realloc_reuses_region() {
    let (_buf, ka) = fresh_heap(64 * 1024);
    let l = layout(256, 16);
    // SAFETY: valid layout, initialized allocator.
    let p1 = unsafe { ka.alloc(l) };
    assert!(!p1.is_null());
    // SAFETY: just allocated.
    unsafe { ka.dealloc(p1, l) };
    // SAFETY: valid layout.
    let p2 = unsafe { ka.alloc(l) };
    assert!(!p2.is_null());
    #[cfg(not(feature = "debug-heappoison"))]
    assert_eq!(p1, p2, "first-fit must reuse the freed region");
    #[cfg(feature = "debug-heappoison")]
    assert_ne!(p1, p2, "quarantine must delay reuse while diagnostics are armed");
    // SAFETY: just allocated.
    unsafe { ka.dealloc(p2, l) };
}

#[cfg(feature = "debug-heappoison")]
#[test]
#[should_panic(expected = "heap redzone corrupted")]
fn duplicate_after_quarantine_eviction_preserves_free_header() {
    let (_buf, ka) = fresh_heap(QUARANTINE_TEST_REGION_BYTES);
    let l = layout(QUARANTINE_TEST_LAYOUT_BYTES, MIN_HOLE_ALIGN);
    // SAFETY: each allocation is immediately transitioned into quarantine.
    let first = unsafe { ka.alloc(l) };
    unsafe { ka.dealloc(first, l) };
    for _ in 0..poison::QUARANTINE_SLOTS {
        // SAFETY: each pointer returned here is released exactly once.
        let ptr = unsafe { ka.alloc(l) };
        assert!(!ptr.is_null());
        unsafe { ka.dealloc(ptr, l) };
    }
    // SAFETY: intentional stale second release; validation must reject it
    // before debug poisoning can overwrite the free-list header at `first`.
    unsafe { ka.dealloc(first, l) };
}

#[cfg(feature = "debug-heappoison")]
#[test]
fn quarantine_does_not_outlive_its_allocator() {
    let l = layout(QUARANTINE_TEST_LAYOUT_BYTES, MIN_HOLE_ALIGN);
    {
        let (_buf, ka) = fresh_heap(QUARANTINE_TEST_REGION_BYTES);
        // SAFETY: pointer is valid and released once into this allocator's ring.
        let ptr = unsafe { ka.alloc(l) };
        unsafe { ka.dealloc(ptr, l) };
    }
    let (_buf, ka) = fresh_heap(QUARANTINE_TEST_REGION_BYTES);
    // SAFETY: a fresh allocator has no stale raw slots from the previous one.
    let ptr = unsafe { ka.alloc(l) };
    unsafe { ka.dealloc(ptr, l) };
}

#[cfg(not(feature = "debug-heappoison"))]
#[test]
fn many_small_allocs_then_free_all_then_one_big() {
    let (_buf, ka) = fresh_heap(64 * 1024);
    let small = layout(64, 8);
    let mut ptrs: Vec<*mut u8> = Vec::new();
    // Fill heap with small allocations.
    loop {
        // SAFETY: valid small layout.
        let p = unsafe { ka.alloc(small) };
        if p.is_null() { break; }
        ptrs.push(p);
    }
    assert!(ptrs.len() > 100, "expected many small allocations to fit");

    // Free in reverse order.
    while let Some(p) = ptrs.pop() {
        // SAFETY: every ptr came from `alloc(small)`.
        unsafe { ka.dealloc(p, small) };
    }

    // After full free + coalesce, a single big allocation should fit.
    let big = layout(32 * 1024, 64);
    // SAFETY: valid big layout.
    let p = unsafe { ka.alloc(big) };
    assert!(!p.is_null(), "coalescing must restore one large hole");
    // SAFETY: just allocated.
    unsafe { ka.dealloc(p, big) };
}

#[test]
fn oom_when_request_exceeds_heap() {
    let (_buf, ka) = fresh_heap(8 * 1024);
    let too_big = layout(64 * 1024, 8);
    // SAFETY: valid layout.
    let p = unsafe { ka.alloc(too_big) };
    assert!(p.is_null());
}

#[cfg(not(feature = "debug-heappoison"))]
#[test]
fn oom_after_exhausting_heap_then_recovers_after_free() {
    let (_buf, ka) = fresh_heap(8 * 1024);
    let l = layout(1024, 8);
    let mut ptrs: Vec<*mut u8> = Vec::new();
    loop {
        // SAFETY: valid layout.
        let p = unsafe { ka.alloc(l) };
        if p.is_null() { break; }
        ptrs.push(p);
    }
    // SAFETY: valid layout, all heap exhausted.
    let p = unsafe { ka.alloc(l) };
    assert!(p.is_null());
    // Free one.
    let freed = ptrs.pop().unwrap();
    // SAFETY: came from alloc above.
    unsafe { ka.dealloc(freed, l) };
    // Now next alloc succeeds.
    // SAFETY: valid layout.
    let p2 = unsafe { ka.alloc(l) };
    assert!(!p2.is_null());

    // Cleanup.
    // SAFETY: came from alloc above.
    unsafe { ka.dealloc(p2, l) };
    while let Some(p) = ptrs.pop() {
        // SAFETY: each came from alloc.
        unsafe { ka.dealloc(p, l) };
    }
}

#[test]
fn high_alignment_request_satisfied() {
    let (_buf, ka) = fresh_heap(64 * 1024);
    for align_log2 in 3..=12u32 {
        let align = 1usize << align_log2;
        let l = layout(64, align);
        // SAFETY: valid layout.
        let p = unsafe { ka.alloc(l) };
        assert!(!p.is_null(), "alloc failed at align {align}");
        assert_eq!(p as usize % align, 0, "ptr {p:?} not aligned to {align}");
        // SAFETY: just allocated.
        unsafe { ka.dealloc(p, l) };
    }
}

#[cfg(not(feature = "debug-heappoison"))]
#[test]
fn interleaved_alloc_free_pattern() {
    // Stress: deterministic pseudo-random alloc/free pattern. After the
    // run, freeing every outstanding ptr must leave the heap usable for
    // one big allocation (= coalescing works under churn).
    let (_buf, ka) = fresh_heap(128 * 1024);
    let mut state: u64 = 0xfeed_face_cafe_babe;
    let mut live: Vec<(*mut u8, Layout)> = Vec::new();
    for _ in 0..2000 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let action = state & 1;
        let size = (((state >> 4) & 0x1ff) + 8) as usize; // 8..520
        let align_log2 = ((state >> 16) & 3) as u32 + 3;  // 8..64
        let align = 1usize << align_log2;
        let l = layout(size, align);
        if action == 0 || live.is_empty() {
            // SAFETY: valid layout.
            let p = unsafe { ka.alloc(l) };
            if !p.is_null() {
                assert_eq!(p as usize % align, 0);
                live.push((p, l));
            }
        } else {
            let idx = ((state >> 32) as usize) % live.len();
            let (p, l_old) = live.swap_remove(idx);
            // SAFETY: came from alloc with l_old.
            unsafe { ka.dealloc(p, l_old) };
        }
    }
    // Drain remaining.
    while let Some((p, l_old)) = live.pop() {
        // SAFETY: came from alloc.
        unsafe { ka.dealloc(p, l_old) };
    }
    // Whole heap should be reclaimable.
    let big = layout(96 * 1024, 64);
    // SAFETY: valid layout.
    let p = unsafe { ka.alloc(big) };
    assert!(!p.is_null(), "coalescing failed under churn");
    // SAFETY: just allocated.
    unsafe { ka.dealloc(p, big) };
}

#[test]
fn writes_to_allocated_memory_dont_clobber_others() {
    // Two simultaneous live allocations; writing to one must not
    // overlap the other.
    let (_buf, ka) = fresh_heap(16 * 1024);
    let l = layout(256, 16);
    // SAFETY: valid layout, initialized.
    let p1 = unsafe { ka.alloc(l) };
    let p2 = unsafe { ka.alloc(l) };
    assert!(!p1.is_null() && !p2.is_null());
    assert_ne!(p1, p2);
    // SAFETY: pointers from alloc; layout::size = 256 each, distinct
    // regions.
    unsafe {
        core::ptr::write_bytes(p1, 0xAA, 256);
        core::ptr::write_bytes(p2, 0x55, 256);
    }
    // SAFETY: just wrote AA / 55 above; reading back.
    unsafe {
        for i in 0..256 {
            assert_eq!(*p1.add(i), 0xAA);
            assert_eq!(*p2.add(i), 0x55);
        }
        ka.dealloc(p1, l);
        ka.dealloc(p2, l);
    }
}

// F247 (T16): the grow hook must satisfy an alloc that the initial
// heap cannot. Set up a small heap, hand back a bigger region from
// the hook, and watch alloc retry-succeed.
use std::sync::Mutex;
const GROW_TEST_TINY_HEAP: usize = 16 * 1024;
const GROW_TEST_BIG_ALLOC: usize = MIB;
const GROW_TEST_BIG_ALIGN: usize = 64;
const GROW_TEST_REGION_BYTES: usize = 4 * MIB;
static GROW_REGIONS: Mutex<Vec<Box<[u8]>>> = Mutex::new(Vec::new());
static GROW_MEMCG: AtomicU64 = AtomicU64::new(NO_MEMCG_CONTEXT);
fn grow_with_big_buffer(min: usize, _memcg: u64) -> Option<(usize, usize)> {
    let mut v = vec![0u8; min.max(GROW_TEST_REGION_BYTES)];
    let start = v.as_mut_ptr() as usize;
    let len   = v.len();
    GROW_REGIONS.lock().unwrap().push(v.into_boxed_slice());
    Some((start, len))
}

fn grow_recording_memcg(min: usize, memcg: u64) -> Option<(usize, usize)> {
    GROW_MEMCG.store(memcg, Ordering::Release);
    grow_with_big_buffer(min, memcg)
}

const OUTER_MEMCG: u64 = 41;
const INNER_MEMCG: u64 = 42;

#[test]
fn allocation_context_nests_and_restores_exact_owner() {
    let (_buf, ka) = fresh_heap(8 * 1024);
    assert_eq!(ka.active_memcg(), NO_MEMCG_CONTEXT);
    let outer = ka.enter_context(AllocationContext::memcg(OUTER_MEMCG));
    assert_eq!(ka.active_memcg(), OUTER_MEMCG);
    {
        let inner = ka.enter_context(AllocationContext::memcg(INNER_MEMCG));
        assert_eq!(ka.active_memcg(), INNER_MEMCG);
        drop(inner);
    }
    assert_eq!(ka.active_memcg(), OUTER_MEMCG);
    drop(outer);
    assert_eq!(ka.active_memcg(), NO_MEMCG_CONTEXT);
}

#[test]
fn explicit_context_reaches_the_growth_owner() {
    let (_buf, ka) = fresh_heap(GROW_TEST_TINY_HEAP);
    let big = Layout::from_size_align(GROW_TEST_BIG_ALLOC, GROW_TEST_BIG_ALIGN).unwrap();
    GROW_MEMCG.store(NO_MEMCG_CONTEXT, Ordering::Release);
    ka.set_grow_hook(grow_recording_memcg);
    let scope = ka.enter_context(AllocationContext::memcg(OUTER_MEMCG));
    // SAFETY: valid layout and initialized allocator.
    let ptr = unsafe { ka.alloc(big) };
    assert!(!ptr.is_null());
    assert_eq!(GROW_MEMCG.load(Ordering::Acquire), OUTER_MEMCG);
    // SAFETY: ptr came from the allocation above using this layout.
    unsafe { ka.dealloc(ptr, big) };
    drop(scope);
}

#[test]
fn grow_hook_satisfies_over_capacity_alloc() {
    // Static-like tiny heap.
    let buf: Vec<u8> = vec![0u8; GROW_TEST_TINY_HEAP];
    let mut buf = buf.into_boxed_slice();
    let ka = KAlloc::new();
    unsafe { ka.init(buf.as_mut_ptr() as usize, buf.len()) };

    // Layout much bigger than the tiny static heap.
    let big = Layout::from_size_align(GROW_TEST_BIG_ALLOC, GROW_TEST_BIG_ALIGN).unwrap();
    // SAFETY: KAlloc has no grow hook yet — verify OOM first.
    let p_oom = unsafe { ka.alloc(big) };
    assert!(p_oom.is_null(), "expected OOM before grow hook installed");

    // Wire the hook + retry.
    ka.set_grow_hook(grow_with_big_buffer);
    let p_ok = unsafe { ka.alloc(big) };
    assert!(!p_ok.is_null(), "alloc should succeed via grow hook");
    unsafe { ka.dealloc(p_ok, big) };
}

// Corruption-hunt hosted repro (state.md: "BREAKTHROUGH LEAD"): a live boot
// found a free-list node whose header bytes were exactly kalloc's own
// quarantine poison (0xEE), meaning the free list held a stale reference
// to memory the quarantine ring currently owns live. Drive alloc/free
// through the carve/quarantine boundary many times, cross-checking after
// every op that no free-list address falls inside a currently-live
// quarantine slot -- if the boot-observed defect reproduces hosted, this
// fails in milliseconds instead of a 500s boot.
#[cfg(feature = "debug-heappoison")]
const QUAR_FUZZ_REGION_BYTES: usize = 1024 * 1024;
#[cfg(feature = "debug-heappoison")]
const QUAR_FUZZ_ROUNDS: usize = 20_000;
#[cfg(feature = "debug-heappoison")]
const QUAR_FUZZ_INFLIGHT_CAP: usize = 5;

#[cfg(feature = "debug-heappoison")]
#[test]
fn free_list_never_overlaps_a_live_quarantine_slot() {
    let (_buf, ka) = fresh_heap(QUAR_FUZZ_REGION_BYTES);
    // Sizes chosen to straddle MIN_HOLE_ALIGN boundaries so carve/split
    // leaves front_pad/back_pad remnants right at the leaked-vs-kept edge.
    let sizes = [1usize, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 200, 512];
    let mut inflight: Vec<(*mut u8, Layout)> = Vec::new();
    for round in 0..QUAR_FUZZ_ROUNDS {
        let size = sizes[round % sizes.len()];
        let align = if round % 3 == 0 { MIN_HOLE_ALIGN } else { MIN_HOLE_ALIGN * 2 };
        let l = layout(size, align);
        // SAFETY: ka initialized above; layout valid.
        let p = unsafe { ka.alloc(l) };
        if !p.is_null() {
            inflight.push((p, l));
        }
        while inflight.len() > QUAR_FUZZ_INFLIGHT_CAP {
            let (fp, fl) = inflight.remove(0);
            // SAFETY: fp/fl came from ka.alloc above and haven't been freed.
            unsafe { ka.dealloc(fp, fl) };
        }
        let g = ka.inner.lock();
        let mut violation: Option<(usize, u64, u32)> = None;
        g.holes.for_each_free(|addr, _size| {
            if violation.is_some() { return; }
            if let Some((base, qsize, _free_ip)) = g.quarantine.lookup(addr as u64) {
                violation = Some((addr, base, qsize));
            }
        });
        drop(g);
        if let Some((addr, base, qsize)) = violation {
            panic!(
                "free-list node at {addr:#x} overlaps a live quarantine slot base={base:#x} size={qsize} (round {round})"
            );
        }
    }
    for (fp, fl) in inflight {
        // SAFETY: still-owned allocations from this test's loop above.
        unsafe { ka.dealloc(fp, fl) };
    }
}
