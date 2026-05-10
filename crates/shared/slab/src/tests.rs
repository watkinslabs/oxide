// Hosted slab tests + proptest oracle per `12§6`. Same HostedBacking
// pattern as pmm tests.

use super::*;
use core::sync::atomic::AtomicU64;
use proptest::prelude::*;
use std::boxed::Box;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::thread;
use std::vec::Vec;
use sync::HostedCpuLocal;

const PAGE_BYTES: usize = PAGE_SIZE_BYTES as usize;

// ---------------------------------------------------------------------------
// HostedBacking — shared with pmm tests in spirit; redeclared here to
// keep slab self-contained for the test runner.
// ---------------------------------------------------------------------------

struct HostedBacking {
    pages: *mut u8,
    n_pages: u64,
    bitmaps: [&'static [AtomicU64]; pmm::ORDERS],
}

// SAFETY: leaked buffer; only Pmm accesses via page_ptr serialized by Spinlock.
unsafe impl Send for HostedBacking {}
// SAFETY: see Send.
unsafe impl Sync for HostedBacking {}

impl HostedBacking {
    fn new(n_pages: u64) -> Self {
        // Page-aligned allocation per `PageBacking::page_ptr` contract.
        let total = (n_pages as usize) * PAGE_BYTES;
        let layout = std::alloc::Layout::from_size_align(total, PAGE_BYTES).unwrap();
        // SAFETY: layout has nonzero size and a valid alignment for std::alloc.
        let pages = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!pages.is_null(), "page-aligned alloc failed");
        let mut bitmaps = [&[][..]; pmm::ORDERS];
        for o in 0..pmm::ORDERS {
            let blocks = (n_pages + (1u64 << o) - 1) >> o;
            let words = ((blocks + 63) >> 6) as usize;
            let v: Vec<AtomicU64> = (0..words.max(1)).map(|_| AtomicU64::new(0)).collect();
            bitmaps[o] = Box::leak(v.into_boxed_slice());
        }
        Self { pages, n_pages, bitmaps }
    }
}

impl PageBacking for HostedBacking {
    unsafe fn page_ptr(&self, pfn: Pfn) -> *mut u8 {
        debug_assert!(pfn.0 < self.n_pages);
        // SAFETY: pfn < n_pages per debug_assert; offset stays inside buf.
        unsafe { self.pages.add((pfn.0 as usize) * PAGE_BYTES) }
    }
    fn bitmap_storage(&self, order: u8, len_u64: usize) -> &'static [AtomicU64] {
        let s = self.bitmaps[order as usize];
        assert!(s.len() >= len_u64);
        s
    }
}

fn build_pmm(n_pages: u64) -> &'static Pmm<HostedBacking> {
    let b = HostedBacking::new(n_pages);
    let pmm = Pmm::init(b, &[pmm::UsableRegion { start: Pfn(0), len_pfn: n_pages }]).unwrap();
    Box::leak(Box::new(pmm))
}

fn cache_for<T>(name: &'static str, pmm_pages: u64) -> Cache<T, HostedBacking> {
    let pmm = build_pmm(pmm_pages);
    Cache::new(pmm, name)
}

// ---------------------------------------------------------------------------
// (1) Layout sanity.
// ---------------------------------------------------------------------------

#[test]
fn layout_8b_obj_min_slot_16() {
    let l = CacheLayout::for_raw(8, 8);
    assert!(l.obj_size >= 16, "min slot 16B for poison+offset");
    // Spec `12§1` I1: align = max(min(8, 64), 8) = 8.
    assert_eq!(l.obj_align, 8);
}

#[test]
fn layout_64b_obj() {
    let l = CacheLayout::for_raw(64, 8);
    assert_eq!(l.obj_size, 64);
    assert_eq!(l.obj_align, 64);  // max(min(64, 64), 8) = 64
}

#[test]
fn layout_128b_obj() {
    let l = CacheLayout::for_raw(128, 8);
    assert_eq!(l.obj_size, 128);
    assert_eq!(l.obj_align, 64);  // capped at 64
}

#[test]
fn layout_packs_many_objs_per_page() {
    let l = CacheLayout::for_raw(64, 8);
    assert!(l.nr_objs > 50, "expected ≥50 64B slots/page, got {}", l.nr_objs);
}

// ---------------------------------------------------------------------------
// (2) Basic alloc / free.
// ---------------------------------------------------------------------------

#[test]
fn alloc_returns_aligned_ptr_64b() {
    let c: Cache<[u8; 64], _> = cache_for("a64", 64);
    let p = c.alloc().unwrap();
    let addr = p.as_ptr() as usize;
    let l = c.layout();
    assert_eq!(addr % l.obj_align as usize, 0);
}

#[test]
fn alloc_then_free_audits_clean() {
    let c: Cache<[u8; 32], _> = cache_for("a32", 64);
    let p = c.alloc().unwrap();
    assert_eq!(c.allocated(), 1);
    // SAFETY: just allocated above from this cache.
    unsafe { c.free(p) };
    assert_eq!(c.allocated(), 0);
}

#[test]
fn alloc_drains_one_slab_page_full() {
    let c: Cache<[u8; 64], _> = cache_for("a64-drain", 64);
    let layout = c.layout();
    let n = layout.nr_objs as usize;
    let mut held: Vec<NonNull<[u8; 64]>> = Vec::with_capacity(n);
    for _ in 0..n {
        held.push(c.alloc().unwrap());
    }
    assert_eq!(c.allocated(), n as u64);
    assert_eq!(c.total_slabs(), 1);
    // One more alloc must cause a fresh slab page from PMM.
    let extra = c.alloc().unwrap();
    held.push(extra);
    assert_eq!(c.total_slabs(), 2);
    for p in held {
        // SAFETY: each p was just allocated above.
        unsafe { c.free(p) };
    }
}

#[test]
fn many_alloc_free_cycles() {
    let c: Cache<[u8; 32], _> = cache_for("cycle", 128);
    for _ in 0..20 {
        let mut held = Vec::new();
        for _ in 0..50 {
            held.push(c.alloc().unwrap());
        }
        for p in held {
            // SAFETY: just allocated above.
            unsafe { c.free(p) };
        }
        assert_eq!(c.allocated(), 0);
    }
}

#[test]
fn alloc_unique_pointers() {
    let c: Cache<[u8; 64], _> = cache_for("uniq", 32);
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    let n = c.layout().nr_objs as usize * 3;  // force multi-page
    let mut held = Vec::with_capacity(n);
    for _ in 0..n {
        let p = c.alloc().unwrap();
        let inserted = seen.insert(p.as_ptr() as usize);
        assert!(inserted, "alloc returned dup pointer");
        held.push(p);
    }
    for p in held {
        // SAFETY: each p was just allocated above.
        unsafe { c.free(p) };
    }
}

// ---------------------------------------------------------------------------
// (3) Drained reserve + PMM return.
// ---------------------------------------------------------------------------

#[test]
fn excess_drained_returns_to_pmm() {
    let c: Cache<[u8; 256], _> = cache_for("ret", 32);
    let layout = c.layout();
    let per_slab = layout.nr_objs as usize;
    // Allocate enough to fill DRAINED_RESERVE+2 slabs.
    let n_slabs_needed = (DRAINED_RESERVE as usize) + 2;
    let total = per_slab * n_slabs_needed;
    let mut held = Vec::with_capacity(total);
    for _ in 0..total { held.push(c.alloc().unwrap()); }
    assert_eq!(c.total_slabs(), n_slabs_needed as u32);
    for p in held {
        // SAFETY: p just allocated.
        unsafe { c.free(p) };
    }
    // Magazines hold up to MAG_SIZE freed objs; flush them so all
    // slabs are eligible for drain/PMM-return.
    c.drain_local_magazine();
    assert!(c.total_slabs() <= DRAINED_RESERVE,
        "got total_slabs={} expected ≤{}", c.total_slabs(), DRAINED_RESERVE);
}

// ---------------------------------------------------------------------------
// (4) Hardening — should_panic cases.
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "double free")]
fn double_free_detected() {
    let c: Cache<[u8; 64], _> = cache_for("dbl", 32);
    let p = c.alloc().unwrap();
    // SAFETY: just allocated.
    unsafe { c.free(p) };
    // SAFETY: deliberate double-free for detector exercise.
    unsafe { c.free(p) };
}

#[test]
#[should_panic(expected = "wrong cache")]
fn wrong_cache_free_detected() {
    let c1: Cache<[u8; 64], _> = cache_for("c1", 32);
    let c2: Cache<[u8; 64], _> = Cache::new(
        // share PMM with a fresh allocator instance to give c2 access
        // to the same address space; simplest is to alloc from c1's
        // PMM via a sibling Cache. We need access to c1's pmm — for
        // the test, build c2 over a distinct PMM and alloc from THAT
        // PMM, then attempt to free into c1.
        build_pmm(32),
        "c2",
    );
    let p_c2 = c2.alloc().unwrap();
    // SAFETY: deliberately wrong cache to exercise cache_id check.
    unsafe { c1.free(p_c2) };
}

#[test]
#[should_panic(expected = "slot misaligned")]
fn misaligned_free_detected() {
    let c: Cache<[u8; 64], _> = cache_for("mis", 32);
    let p = c.alloc().unwrap();
    let bad = unsafe { NonNull::new_unchecked((p.as_ptr() as *mut u8).add(1) as *mut [u8; 64]) };
    // SAFETY: deliberately misaligned to exercise alignment check.
    unsafe { c.free(bad) };
}

// ---------------------------------------------------------------------------
// (5) Concurrent stress.
// ---------------------------------------------------------------------------

#[test]
fn concurrent_alloc_free_no_corruption() {
    // 4 threads × 200 alloc-then-free cycles; final state clean.
    // Uses HostedCpuLocal so each thread gets a unique magazine slot
    // — NoopCpuLocal would alias all threads onto slot 0 (UB under
    // PerCpu's preempt-off contract per `06§4`).
    let pmm = build_pmm(128);
    let cache: Arc<Cache<[u8; 32], HostedBacking, NoopIrq, HostedCpuLocal>> =
        Arc::new(Cache::new(pmm, "conc"));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let c = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            for _ in 0..200 {
                let p = c.alloc().unwrap();
                // Write a recognizable pattern, then free.
                // SAFETY: p is fresh from alloc; this thread has exclusive access.
                unsafe { core::ptr::write(p.as_ptr(), [0xABu8; 32]) };
                // SAFETY: just allocated.
                unsafe { c.free(p) };
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
    assert_eq!(cache.allocated(), 0);
}

#[test]
fn concurrent_unique_pointers_no_overlap() {
    let pmm = build_pmm(64);
    let cache: Arc<Cache<[u8; 64], HostedBacking, NoopIrq, HostedCpuLocal>> =
        Arc::new(Cache::new(pmm, "uniqc"));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let c = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            // NonNull is !Send; ferry as usize across threads.
            let mut local: Vec<usize> = Vec::with_capacity(50);
            for _ in 0..50 { local.push(c.alloc().unwrap().as_ptr() as usize); }
            local
        }));
    }
    let mut all: Vec<usize> = Vec::new();
    for h in handles { all.extend(h.join().unwrap()); }
    // Verify all addresses unique.
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    for &addr in &all {
        let inserted = seen.insert(addr);
        assert!(inserted, "concurrent alloc returned dup pointer");
    }
    for addr in all {
        // SAFETY: addr was returned by Pmm::alloc on this cache; convert back to NonNull and free.
        let p = unsafe { NonNull::new_unchecked(addr as *mut [u8; 64]) };
        // SAFETY: just allocated.
        unsafe { cache.free(p) };
    }
    assert_eq!(cache.allocated(), 0);
}

// ---------------------------------------------------------------------------
// (6) Proptest oracle. BTreeMap-of-outstanding agreement.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Op { Alloc, FreeNth(usize) }

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        (Just(Op::Alloc)),
        (0usize..256).prop_map(Op::FreeNth),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 100, max_shrink_iters: 512, .. ProptestConfig::default()
    })]

    #[test]
    fn oracle_agreement(ops in proptest::collection::vec(op_strategy(), 1..400)) {
        let cache: Cache<[u8; 64], _> = cache_for("oracle", 128);
        let mut outstanding: BTreeMap<usize, NonNull<[u8; 64]>> = BTreeMap::new();
        for op in ops {
            match op {
                Op::Alloc => match cache.alloc() {
                    Ok(p) => {
                        let key = p.as_ptr() as usize;
                        prop_assert!(!outstanding.contains_key(&key), "alloc returned outstanding pointer");
                        outstanding.insert(key, p);
                    }
                    Err(Error::NoMem) => {}
                    Err(e) => prop_assert!(false, "unexpected alloc err {:?}", e),
                },
                Op::FreeNth(idx) => {
                    if outstanding.is_empty() { continue; }
                    let keys: Vec<usize> = outstanding.keys().copied().collect();
                    let k = keys[idx % keys.len()];
                    let p = outstanding.remove(&k).unwrap();
                    // SAFETY: p tracked outstanding ⇒ valid alloc, not yet freed.
                    unsafe { cache.free(p) };
                }
            }
            prop_assert_eq!(cache.allocated(), outstanding.len() as u64);
        }
        // Drain leftover.
        let leftover: Vec<NonNull<[u8; 64]>> = outstanding.into_values().collect();
        for p in leftover {
            // SAFETY: oracle-tracked outstanding ⇒ valid.
            unsafe { cache.free(p) };
        }
        prop_assert_eq!(cache.allocated(), 0);
    }
}

// ---------------------------------------------------------------------------
// (7) Sized variety — verify several common sizes work end-to-end.
// ---------------------------------------------------------------------------

macro_rules! roundtrip_test {
    ($name:ident, $size:literal) => {
        #[test]
        fn $name() {
            let c: Cache<[u8; $size], _> = cache_for(stringify!($name), 64);
            let mut held = Vec::new();
            for _ in 0..32 { held.push(c.alloc().unwrap()); }
            for p in held {
                // SAFETY: each p just allocated above.
                unsafe { c.free(p) };
            }
            assert_eq!(c.allocated(), 0);
        }
    };
}

roundtrip_test!(roundtrip_8,    8);
roundtrip_test!(roundtrip_16,   16);
roundtrip_test!(roundtrip_32,   32);
roundtrip_test!(roundtrip_64,   64);
roundtrip_test!(roundtrip_96,   96);
roundtrip_test!(roundtrip_128,  128);
roundtrip_test!(roundtrip_256,  256);
roundtrip_test!(roundtrip_512,  512);
roundtrip_test!(roundtrip_1024, 1024);
