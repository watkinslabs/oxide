use super::*;

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
    let ka = Box::new(KAlloc::new());
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

// Same invariant as above, but exercising the two dimensions the
// single-threaded harness above does NOT cover, per state.md's "next
// candidates" note: (a) real concurrent alloc/dealloc/quarantine access
// from multiple threads pounding the SAME KAlloc (every live boot that hit
// this ran under real multi-process desktop load), and (b) a tiny static
// heap + grow hook, so `kalloc_grow`/`HoleList::add_region` gets exercised
// interleaved with quarantine activity instead of running over one large
// fixed arena that never needs to grow.
#[cfg(feature = "debug-heappoison")]
const QUAR_SMP_FUZZ_THREADS: usize = 4;
#[cfg(feature = "debug-heappoison")]
const QUAR_SMP_FUZZ_ROUNDS_PER_THREAD: usize = 4000;
#[cfg(feature = "debug-heappoison")]
const QUAR_SMP_FUZZ_CHECK_EVERY: usize = 8;

#[cfg(feature = "debug-heappoison")]
#[test]
fn concurrent_alloc_free_never_lets_free_list_overlap_quarantine() {
    let (_buf, ka) = fresh_heap(GROW_TEST_TINY_HEAP);
    ka.set_grow_hook(grow_with_big_buffer);
    let sizes = [1usize, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 200, 512];
    let violation: Mutex<Option<std::string::String>> = Mutex::new(None);
    std::thread::scope(|scope| {
        for t in 0..QUAR_SMP_FUZZ_THREADS {
            let ka_ref = &ka;
            let violation_ref = &violation;
            let sizes_ref = &sizes;
            scope.spawn(move || {
                let mut inflight: Vec<(*mut u8, Layout)> = Vec::new();
                for round in 0..QUAR_SMP_FUZZ_ROUNDS_PER_THREAD {
                    if violation_ref.lock().unwrap().is_some() { break; }
                    let size = sizes_ref[(round + t) % sizes_ref.len()];
                    let align = if (round + t) % 3 == 0 { MIN_HOLE_ALIGN } else { MIN_HOLE_ALIGN * 2 };
                    let l = layout(size, align);
                    // SAFETY: ka initialized before threads spawn; layout valid.
                    let p = unsafe { ka_ref.alloc(l) };
                    if !p.is_null() { inflight.push((p, l)); }
                    while inflight.len() > QUAR_FUZZ_INFLIGHT_CAP {
                        let (fp, fl) = inflight.remove(0);
                        // SAFETY: fp/fl came from ka_ref.alloc above and haven't been freed.
                        unsafe { ka_ref.dealloc(fp, fl) };
                    }
                    if round % QUAR_SMP_FUZZ_CHECK_EVERY != 0 { continue; }
                    let g = ka_ref.inner.lock();
                    let mut hit: Option<(usize, u64, u32)> = None;
                    g.holes.for_each_free(|addr, _size| {
                        if hit.is_some() { return; }
                        if let Some((base, qsize, _free_ip)) = g.quarantine.lookup(addr as u64) {
                            hit = Some((addr, base, qsize));
                        }
                    });
                    drop(g);
                    if let Some((addr, base, qsize)) = hit {
                        *violation_ref.lock().unwrap() = Some(std::format!(
                            "thread {t} round {round}: free-list node {addr:#x} overlaps live quarantine slot base={base:#x} size={qsize}"
                        ));
                        break;
                    }
                }
                for (fp, fl) in inflight {
                    // SAFETY: still-owned allocations from this thread's loop above.
                    unsafe { ka_ref.dealloc(fp, fl) };
                }
            });
        }
    });
    let taken = violation.lock().unwrap().take();
    if let Some(msg) = taken {
        panic!("{msg}");
    }
}

// ---------------------------------------------------------------------------
// `kmalloc` size-class front end (`sizeclass.rs`).
// ---------------------------------------------------------------------------

#[cfg(not(any(feature = "debug-heappoison", feature = "debug-dealloc-diag",
              feature = "debug-hw-watchpoint", feature = "debug-efence")))]
#[test]
fn size_class_routing_matches_the_kmalloc_cache_table() {
    use crate::sizeclass::{class_index, CLASS_SIZES, MAX_CLASS_BYTES, SLAB_ALIGN};
    // Exact cache sizes route to themselves; one byte over rolls to the next.
    for (i, &c) in CLASS_SIZES.iter().enumerate() {
        assert_eq!(class_index(layout(c, 8)), Some(i), "size {c} routes to its own cache");
    }
    assert_eq!(class_index(layout(17, 8)), Some(1), "17 bytes rounds up to the 32 cache");
    assert_eq!(class_index(layout(97, 8)), Some(4), "97 bytes rounds up to the 128 cache");
    // Out of range in either dimension stays on the hole list.
    assert_eq!(class_index(layout(MAX_CLASS_BYTES + 1, 8)), None, "over-size leaves kmalloc");
    assert_eq!(class_index(layout(64, SLAB_ALIGN * 2)), None, "over-alignment leaves kmalloc");
    // A stride that cannot carry the requested alignment is not routed: 96 is
    // not a multiple of 64, so 96-byte objects cannot all be 64-aligned.
    assert_eq!(class_index(layout(96, 64)), None, "stride must carry the alignment");
    assert_eq!(class_index(layout(0, 8)), None, "zero-size request is not a cache request");
}

#[cfg(not(any(feature = "debug-heappoison", feature = "debug-dealloc-diag",
              feature = "debug-hw-watchpoint", feature = "debug-efence")))]
#[test]
fn size_class_allocations_are_distinct_aligned_and_reusable() {
    let (_buf, ka) = fresh_heap(1024 * 1024);
    let l = layout(64, 16);
    let mut seen: Vec<*mut u8> = Vec::new();
    for _ in 0..2000 {
        // SAFETY: valid layout on an initialized allocator.
        let p = unsafe { ka.alloc(l) };
        assert!(!p.is_null(), "class allocation must be served");
        assert_eq!(p as usize % 16, 0, "class object must carry the requested alignment");
        seen.push(p);
    }
    let mut sorted = seen.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), seen.len(), "class must never hand out the same object twice");
    // Every object must be writable without disturbing its neighbours.
    for (i, p) in seen.iter().enumerate() {
        // SAFETY: each `p` is a live 64-byte allocation owned by this test.
        unsafe { core::ptr::write_bytes(*p, (i % 251) as u8, 64) };
    }
    for (i, p) in seen.iter().enumerate() {
        // SAFETY: same live allocation, written just above.
        let v = unsafe { core::ptr::read(*p) };
        assert_eq!(v, (i % 251) as u8, "class objects must not overlap");
    }
    for p in seen.drain(..) {
        // SAFETY: allocated above with exactly `l`.
        unsafe { ka.dealloc(p, l) };
    }
    // A freed object comes straight back (LIFO), without a hole-list walk.
    // SAFETY: valid layout.
    let a = unsafe { ka.alloc(l) };
    // SAFETY: just allocated.
    unsafe { ka.dealloc(a, l) };
    // SAFETY: valid layout.
    let b = unsafe { ka.alloc(l) };
    assert_eq!(a, b, "class free list is LIFO");
    // SAFETY: just allocated.
    unsafe { ka.dealloc(b, l) };
}

#[cfg(not(any(feature = "debug-heappoison", feature = "debug-dealloc-diag",
              feature = "debug-hw-watchpoint", feature = "debug-efence")))]
#[test]
fn idle_class_memory_is_reclaimed_when_a_large_request_needs_it() {
    // A cache that once served small objects must not pin that memory against
    // a later large request (Linux `kmem_cache_shrink` / `discard_slab`).
    let (_buf, ka) = fresh_heap(256 * 1024);
    let small = layout(32, 8);
    let mut ptrs: Vec<*mut u8> = Vec::new();
    loop {
        // SAFETY: valid layout.
        let p = unsafe { ka.alloc(small) };
        if p.is_null() { break; }
        ptrs.push(p);
    }
    assert!(ptrs.len() > 1000, "expected the small cache to absorb the heap");
    while let Some(p) = ptrs.pop() {
        // SAFETY: each came from `alloc(small)`.
        unsafe { ka.dealloc(p, small) };
    }
    let big = layout(128 * 1024, 64);
    // SAFETY: valid layout.
    let p = unsafe { ka.alloc(big) };
    assert!(!p.is_null(), "class reclaim must return idle slab memory to the hole list");
    // SAFETY: just allocated.
    unsafe { ka.dealloc(p, big) };
}
