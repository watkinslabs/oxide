// Hosted tests + proptest oracle per `10§9`. Comprehensive coverage:
// boundaries, overflow, alignment, overlap, fragmentation, error
// paths, multi-region, bitmap-word edges, concurrent contention.

use super::*;
use core::sync::atomic::AtomicU64;
use proptest::prelude::*;
use std::boxed::Box;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::thread;
use std::vec;
use std::vec::Vec;

const PAGE: usize = PAGE_SIZE_BYTES as usize;

// ---------------------------------------------------------------------------
// Hosted page + bitmap backing.
// ---------------------------------------------------------------------------

struct HostedBacking {
    pages: *mut u8,
    n_pages: u64,
    bitmaps: [&'static [AtomicU64]; ORDERS],
}

// SAFETY: backing buffer is leaked for the test process lifetime; only
// the owning Pmm dereferences via page_ptr, serialized by Spinlock.
unsafe impl Send for HostedBacking {}
// SAFETY: see Send impl above.
unsafe impl Sync for HostedBacking {}

impl HostedBacking {
    fn new(n_pages: u64) -> Self {
        let buf = vec![0u8; (n_pages.max(1) as usize) * PAGE].into_boxed_slice();
        let pages = Box::leak(buf).as_mut_ptr();
        let mut bitmaps = [&[][..]; ORDERS];
        for o in 0..ORDERS {
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
        // SAFETY: pfn < n_pages per debug_assert; offset stays inside leaked buf.
        unsafe { self.pages.add((pfn.0 as usize) * PAGE) }
    }
    fn bitmap_storage(&self, order: u8, len_u64: usize) -> &'static [AtomicU64] {
        let s = self.bitmaps[order as usize];
        assert!(s.len() >= len_u64,
            "bitmap too small for order {}: have {} need {}", order, s.len(), len_u64);
        s
    }
}

fn build(n_pages: u64) -> Pmm<HostedBacking> {
    let b = HostedBacking::new(n_pages);
    Pmm::init(b, &[UsableRegion { start: Pfn(0), len_pfn: n_pages }]).unwrap()
}

fn build_regions(total_pages: u64, regions: &[UsableRegion]) -> Pmm<HostedBacking> {
    let b = HostedBacking::new(total_pages);
    Pmm::init(b, regions).unwrap()
}

// ---------------------------------------------------------------------------
// (1) Sanity / construction.
// ---------------------------------------------------------------------------

#[test]
fn max_order_invariant() { assert_eq!(MAX_ORDER, 20); }

#[test]
fn poison_magic_invariant() { assert_eq!(POISON_MAGIC, 0xDEAD_BEEF_CAFE_BABE); }

#[test]
fn page_size_matches_hal() { assert_eq!(PAGE_SIZE_BYTES, 4096); }

// ---------------------------------------------------------------------------
// (2) init bound + overflow + overlap defenses.
// ---------------------------------------------------------------------------

#[test]
fn init_empty_regions_returns_err() {
    let b = HostedBacking::new(64);
    assert_eq!(Pmm::init(b, &[]).err(), Some(Error::OutOfRange));
}

#[test]
fn init_overflow_start_plus_len_returns_err() {
    let b = HostedBacking::new(64);
    let r = [UsableRegion { start: Pfn(u64::MAX - 5), len_pfn: 100 }];
    assert_eq!(Pmm::init(b, &r).err(), Some(Error::OutOfRange));
}

#[test]
fn init_overflow_total_returns_err() {
    let b = HostedBacking::new(64);
    let r = [
        UsableRegion { start: Pfn(0),                 len_pfn: u64::MAX / 2 + 1 },
        UsableRegion { start: Pfn(u64::MAX / 2 + 2), len_pfn: u64::MAX / 2 + 1 },
    ];
    // Sum overflows even before we check overlap.
    assert!(matches!(Pmm::init(b, &r).err(), Some(Error::OutOfRange) | Some(Error::Overlap)));
}

#[test]
fn init_overlapping_regions_returns_overlap() {
    let b = HostedBacking::new(256);
    let r = [
        UsableRegion { start: Pfn(0),   len_pfn: 200 },
        UsableRegion { start: Pfn(100), len_pfn: 100 },  // overlaps [100..200) of first
    ];
    assert_eq!(Pmm::init(b, &r).err(), Some(Error::Overlap));
}

#[test]
fn init_adjacent_regions_ok() {
    // touching but not overlapping
    let b = HostedBacking::new(256);
    let r = [
        UsableRegion { start: Pfn(0),   len_pfn: 100 },
        UsableRegion { start: Pfn(100), len_pfn: 100 },
    ];
    let pmm = Pmm::init(b, &r).unwrap();
    assert_eq!(pmm.free_pages(), 200);
}

#[test]
fn init_zero_length_region_skipped() {
    let b = HostedBacking::new(64);
    let r = [
        UsableRegion { start: Pfn(0), len_pfn: 0 },
        UsableRegion { start: Pfn(0), len_pfn: 64 },
    ];
    let pmm = Pmm::init(b, &r).unwrap();
    assert_eq!(pmm.free_pages(), 64);
}

#[test]
fn init_reverse_order_regions_ok() {
    // Caller may pass regions out of address order; init must accept.
    let b = HostedBacking::new(1024);
    let r = [
        UsableRegion { start: Pfn(512), len_pfn: 256 },
        UsableRegion { start: Pfn(0),   len_pfn: 256 },
    ];
    let pmm = Pmm::init(b, &r).unwrap();
    // SAFETY: hosted single-thread; audit takes its own lock.
    unsafe { pmm.audit() };
    assert_eq!(pmm.free_pages(), 512);
}

// ---------------------------------------------------------------------------
// (3) Boundary sizes.
// ---------------------------------------------------------------------------

#[test]
fn single_page_pmm_alloc_then_free() {
    let pmm = build(1);
    let p = pmm.alloc(Order(0)).unwrap();
    assert_eq!(p.0, 0);
    assert_eq!(pmm.allocated_pages(), 1);
    assert_eq!(pmm.alloc(Order(0)), Err(Error::NoMem));
    // SAFETY: just allocated above.
    unsafe { pmm.free(p, Order(0)) };
    assert_eq!(pmm.free_pages(), 1);
}

#[test]
fn exactly_one_max_block_at_max_order() {
    // Use a small "max" by limiting to MAX_ORDER=20 → 1<<20 = 1M pages = 4 GiB.
    // That's heavy for a unit test; pick order 12 = 4096 pages instead and
    // verify the algorithm can return the largest possible block.
    let pmm = build(4096);
    let p = pmm.alloc(Order(12)).unwrap();
    assert_eq!(p.0, 0);
    assert_eq!(pmm.free_pages(), 0);
    assert_eq!(pmm.alloc(Order(0)), Err(Error::NoMem));
    // SAFETY: just allocated above at order 12.
    unsafe { pmm.free(p, Order(12)) };
    assert_eq!(pmm.free_pages(), 4096);
}

#[test]
fn alloc_at_pfn_max_minus_one_via_drain() {
    // Drain the pool one page at a time; verify max pfn allocated is n-1.
    let n = 32u64;
    let pmm = build(n);
    let mut pfns: Vec<u64> = Vec::new();
    while let Ok(p) = pmm.alloc(Order(0)) { pfns.push(p.0); }
    pfns.sort();
    assert_eq!(pfns.len() as u64, n);
    assert_eq!(pfns.first().copied(), Some(0));
    assert_eq!(pfns.last().copied(), Some(n - 1));
}

#[test]
fn non_power_of_two_pool_drains_completely() {
    // 1500 pages ≠ a single buddy block. Verify every page is reachable.
    let n = 1500u64;
    let pmm = build(n);
    let mut pfns: BTreeSet<u64> = BTreeSet::new();
    while let Ok(p) = pmm.alloc(Order(0)) { pfns.insert(p.0); }
    assert_eq!(pfns.len() as u64, n);
    for p in 0..n { assert!(pfns.contains(&p), "missed pfn {}", p); }
}

#[test]
fn bitmap_word_boundary_pfn_63_64() {
    // Exercise the u64 word boundary: pfn 63 is in word 0, pfn 64 is in
    // word 1. Allocate, free, re-allocate around the boundary.
    let pmm = build(256);
    pmm.reserve_early(Pfn(0), 63).unwrap();
    let p63 = pmm.alloc(Order(0)).unwrap();
    let p64 = pmm.alloc(Order(0)).unwrap();
    assert_eq!(p63.0, 63);
    assert_eq!(p64.0, 64);
    // SAFETY: both p63 and p64 just allocated above at order 0.
    unsafe { pmm.free(p63, Order(0)) };
    // SAFETY: see above.
    unsafe { pmm.free(p64, Order(0)) };
    // SAFETY: hosted single-thread; audit takes its own lock.
    unsafe { pmm.audit() };
}

// ---------------------------------------------------------------------------
// (4) alloc / free correctness invariants.
// ---------------------------------------------------------------------------

#[test]
fn alloc_returns_aligned_pfn_explicit() {
    let pmm = build(4096);
    for o in 0..=10u8 {
        let p = pmm.alloc(Order(o)).unwrap();
        assert_eq!(p.0 & ((1u64 << o) - 1), 0,
            "alloc({}) returned misaligned pfn {}", o, p.0);
    }
}

#[test]
fn alloc_zeros_returned_pages() {
    let pmm = build(256);
    let p = pmm.alloc(Order(2)).unwrap();
    let g = pmm.inner.lock();
    for k in 0..(1u64 << 2) {
        // SAFETY: PMM-owned freshly allocated page; ptr valid for one PAGE.
        let ptr = unsafe { g.backing.page_ptr(Pfn(p.0 + k)) };
        for off in 0..PAGE {
            // SAFETY: within the 4 KiB freshly-zeroed page.
            let v = unsafe { core::ptr::read(ptr.add(off)) };
            assert_eq!(v, 0, "page {} byte {} not zeroed", p.0 + k, off);
        }
    }
}

#[test]
fn alloc_rejects_oversized_order() {
    let pmm = build(64);
    assert_eq!(pmm.alloc(Order(MAX_ORDER + 1)), Err(Error::InvalidOrder));
    assert_eq!(pmm.alloc(Order(255)), Err(Error::InvalidOrder));
}

#[test]
fn alloc_oom_returns_nomem() {
    let pmm = build(4);
    let _a = pmm.alloc(Order(2)).unwrap();
    assert_eq!(pmm.alloc(Order(0)), Err(Error::NoMem));
    assert_eq!(pmm.alloc(Order(2)), Err(Error::NoMem));
}

#[test]
fn alloc_each_order_then_free_audits_clean() {
    let pmm = build(4096);
    let mut held: Vec<(Pfn, Order)> = Vec::new();
    for o in 0..=10u8 {
        let p = pmm.alloc(Order(o)).unwrap();
        held.push((p, Order(o)));
        // SAFETY: hosted single-thread; audit takes its own lock.
        unsafe { pmm.audit() };
    }
    for (p, o) in held.into_iter().rev() {
        // SAFETY: each (p,o) was just returned by Pmm::alloc above.
        unsafe { pmm.free(p, o) };
        // SAFETY: hosted single-thread; audit takes its own lock.
        unsafe { pmm.audit() };
    }
    assert_eq!(pmm.allocated_pages(), 0);
    assert_eq!(pmm.free_pages(), 4096);
}

#[test]
fn alloc_all_then_free_random_order_merges_back() {
    let n = 256u64;
    let pmm = build(n);
    let mut pfns: Vec<Pfn> = (0..n).map(|_| pmm.alloc(Order(0)).unwrap()).collect();
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for i in (1..pfns.len()).rev() {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        pfns.swap(i, (x as usize) % (i + 1));
    }
    for p in pfns {
        // SAFETY: every p was just returned by Pmm::alloc(Order(0)).
        unsafe { pmm.free(p, Order(0)) };
    }
    // SAFETY: hosted single-thread; audit takes its own lock.
    unsafe { pmm.audit() };
    assert_eq!(pmm.free_pages(), n);
}

#[test]
fn drain_and_refill_repeatedly() {
    let n = 128u64;
    let pmm = build(n);
    for _ in 0..10 {
        let pfns: Vec<Pfn> = (0..n).map(|_| pmm.alloc(Order(0)).unwrap()).collect();
        assert_eq!(pmm.allocated_pages(), n);
        for p in pfns {
            // SAFETY: just allocated above.
            unsafe { pmm.free(p, Order(0)) };
        }
        assert_eq!(pmm.free_pages(), n);
        // SAFETY: hosted single-thread; audit takes its own lock.
        unsafe { pmm.audit() };
    }
}

// ---------------------------------------------------------------------------
// (5) free input validation (kassert).
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "double free")]
fn double_free_detected() {
    let pmm = build(64);
    let p = pmm.alloc(Order(0)).unwrap();
    // SAFETY: just allocated.
    unsafe { pmm.free(p, Order(0)) };
    // SAFETY: deliberately double-free to exercise detector.
    unsafe { pmm.free(p, Order(0)) };
}

#[test]
#[should_panic(expected = "out of range")]
fn free_out_of_range_kasserts() {
    let pmm = build(64);
    // SAFETY: deliberately bad pfn to exercise range check.
    unsafe { pmm.free(Pfn(64), Order(0)) };
}

#[test]
#[should_panic(expected = "out of range")]
fn free_far_out_of_range_kasserts() {
    let pmm = build(64);
    // SAFETY: deliberately huge pfn to exercise range check.
    unsafe { pmm.free(Pfn(u64::MAX), Order(0)) };
}

#[test]
#[should_panic(expected = "misaligned")]
fn free_misaligned_kasserts() {
    let pmm = build(64);
    // SAFETY: deliberately misaligned pfn for order 3.
    unsafe { pmm.free(Pfn(3), Order(3)) };
}

#[test]
#[should_panic(expected = "invalid order")]
fn free_invalid_order_kasserts() {
    let pmm = build(64);
    // SAFETY: deliberately bad order to exercise order check.
    unsafe { pmm.free(Pfn(0), Order(MAX_ORDER + 1)) };
}

#[test]
#[should_panic(expected = "poison")]
fn corrupted_free_page_caught_on_alloc() {
    let pmm = build(64);
    {
        let g = pmm.inner.lock();
        // SAFETY: corrupting page 0 to exercise poison detection.
        let ptr = unsafe { g.backing.page_ptr(Pfn(0)) };
        // SAFETY: writing into a free page's poison u64; test-only.
        unsafe { core::ptr::write_unaligned(ptr as *mut u64, 0) };
    }
    for _ in 0..64 { let _ = pmm.alloc(Order(0)).unwrap(); }
}

// ---------------------------------------------------------------------------
// (6) reserve_early extensive.
// ---------------------------------------------------------------------------

#[test]
fn reserve_early_zero_length_noop() {
    let pmm = build(128);
    pmm.reserve_early(Pfn(10), 0).unwrap();
    assert_eq!(pmm.allocated_pages(), 0);
    assert_eq!(pmm.free_pages(), 128);
}

#[test]
fn reserve_early_past_pfn_max_returns_err() {
    let pmm = build(128);
    assert_eq!(pmm.reserve_early(Pfn(120), 100), Err(Error::OutOfRange));
}

#[test]
fn reserve_early_overflow_returns_err() {
    let pmm = build(128);
    assert_eq!(pmm.reserve_early(Pfn(u64::MAX - 5), 100), Err(Error::OutOfRange));
}

#[test]
fn reserve_entire_ram_then_alloc_oom() {
    let pmm = build(64);
    pmm.reserve_early(Pfn(0), 64).unwrap();
    assert_eq!(pmm.alloc(Order(0)), Err(Error::NoMem));
    assert_eq!(pmm.allocated_pages(), 64);
    assert_eq!(pmm.free_pages(), 0);
}

#[test]
fn reserve_early_multi_call_idempotent() {
    let pmm = build(512);
    pmm.reserve_early(Pfn(10), 5).unwrap();
    pmm.reserve_early(Pfn(10), 5).unwrap();
    pmm.reserve_early(Pfn(12), 1).unwrap();
    // SAFETY: hosted single-thread; audit takes its own lock.
    unsafe { pmm.audit() };
    assert_eq!(pmm.allocated_pages(), 5);
}

#[test]
fn reserve_early_at_high_boundary() {
    let pmm = build(64);
    pmm.reserve_early(Pfn(63), 1).unwrap();
    // SAFETY: hosted single-thread; audit.
    unsafe { pmm.audit() };
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    while let Ok(p) = pmm.alloc(Order(0)) {
        assert!(p.0 != 63);
        seen.insert(p.0);
    }
    assert_eq!(seen.len(), 63);
}

#[test]
fn reserve_early_then_alloc_avoids_reserved() {
    let n = 256u64;
    let pmm = build(n);
    pmm.reserve_early(Pfn(0), 64).unwrap();
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    while let Ok(p) = pmm.alloc(Order(0)) {
        assert!(p.0 >= 64, "alloc returned reserved pfn {}", p.0);
        seen.insert(p.0);
    }
    assert_eq!(seen.len() as u64, n - 64);
}

#[test]
fn reserve_early_then_audit_clean() {
    let pmm = build(512);
    pmm.reserve_early(Pfn(50),   23).unwrap();
    pmm.reserve_early(Pfn(100),  17).unwrap();
    pmm.reserve_early(Pfn(300),  64).unwrap();  // exactly an order-6 block
    pmm.reserve_early(Pfn(200), 100).unwrap();  // odd-sized middle
    // SAFETY: hosted single-thread; audit.
    unsafe { pmm.audit() };
    assert_eq!(pmm.allocated_pages(), 23 + 17 + 64 + 100);
    assert_eq!(pmm.free_pages(), 512 - (23 + 17 + 64 + 100));
}

// ---------------------------------------------------------------------------
// (7) Multi-region.
// ---------------------------------------------------------------------------

#[test]
fn multi_region_alloc_drains_all_usable() {
    let n_pages = 1024u64;
    let pmm = build_regions(n_pages, &[
        UsableRegion { start: Pfn(0),   len_pfn: 256 },
        UsableRegion { start: Pfn(512), len_pfn: 256 },
    ]);
    let mut pfns: BTreeSet<u64> = BTreeSet::new();
    while let Ok(p) = pmm.alloc(Order(0)) { pfns.insert(p.0); }
    assert_eq!(pfns.len(), 512);
    // No pfn should fall in the gap [256, 512).
    for &p in pfns.iter() { assert!(p < 256 || p >= 512); }
}

#[test]
fn multi_region_alloc_never_crosses_gap() {
    // alloc(8) = 256 pages; the smaller-of-two regions is exactly 256.
    // Verify no allocation spans the gap.
    let n_pages = 1024u64;
    let pmm = build_regions(n_pages, &[
        UsableRegion { start: Pfn(0),   len_pfn: 128 },
        UsableRegion { start: Pfn(640), len_pfn: 128 },
    ]);
    while let Ok(p) = pmm.alloc(Order(0)) {
        // every returned pfn must be in one of the two regions
        let in_first = p.0 < 128;
        let in_second = p.0 >= 640 && p.0 < 768;
        assert!(in_first || in_second, "pfn {} out of all regions", p.0);
    }
}

// ---------------------------------------------------------------------------
// (8) Fragmentation / large-alloc-after-small-frees.
// ---------------------------------------------------------------------------

#[test]
fn checkerboard_fragmentation_blocks_large_alloc() {
    // Allocate every order-0 page, then free every other one. Pool has
    // half its pages free but no order-1 block can be assembled.
    let n = 64u64;
    let pmm = build(n);
    let pfns: Vec<Pfn> = (0..n).map(|_| pmm.alloc(Order(0)).unwrap()).collect();
    // Free even-indexed pfns only (in alloc order — they're 0,1,2,...).
    for (i, p) in pfns.iter().enumerate() {
        if i % 2 == 0 {
            // SAFETY: each p just allocated above.
            unsafe { pmm.free(*p, Order(0)) };
        }
    }
    assert_eq!(pmm.alloc(Order(1)), Err(Error::NoMem));
}

#[test]
fn fragmented_then_defragment_recovers_large_alloc() {
    let n = 64u64;
    let pmm = build(n);
    let pfns: Vec<Pfn> = (0..n).map(|_| pmm.alloc(Order(0)).unwrap()).collect();
    // Free all in any order.
    for p in pfns {
        // SAFETY: each p just allocated above.
        unsafe { pmm.free(p, Order(0)) };
    }
    // After full free, an order-6 (64-page) block must be available.
    let big = pmm.alloc(Order(6)).unwrap();
    assert_eq!(big.0, 0);
}

// ---------------------------------------------------------------------------
// (9) Boot at varied scales.
// ---------------------------------------------------------------------------

#[test]
fn boot_one_megabyte() {
    let n = 1024 * 1024 / PAGE_SIZE_BYTES;  // 256 pages
    let pmm = build(n);
    // SAFETY: hosted single-thread; audit.
    unsafe { pmm.audit() };
    assert_eq!(pmm.free_pages(), n);
}

#[test]
fn boot_ten_megabytes() {
    let n = 10 * 1024 * 1024 / PAGE_SIZE_BYTES;  // 2560 pages
    let pmm = build(n);
    // SAFETY: hosted single-thread; audit.
    unsafe { pmm.audit() };
    assert_eq!(pmm.free_pages(), n);
}

#[test]
fn boot_two_gigabytes() {
    let n = 2u64 * 1024 * 1024 * 1024 / PAGE_SIZE_BYTES;  // 524288 pages = 2^19
    let pmm = build(n);
    // SAFETY: hosted single-thread; audit.
    unsafe { pmm.audit() };
    assert_eq!(pmm.free_pages(), n);
}

// ---------------------------------------------------------------------------
// (10) Concurrent stress.
// ---------------------------------------------------------------------------

#[test]
fn concurrent_alloc_free_smoke() {
    // 4 threads, each does N alloc-then-free cycles. Verifies Spinlock
    // serializes correctly + final state is clean.
    let n_pages = 4096u64;
    let pmm = Arc::new(build(n_pages));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let pmm = Arc::clone(&pmm);
        handles.push(thread::spawn(move || {
            for _ in 0..500 {
                if let Ok(p) = pmm.alloc(Order(0)) {
                    // SAFETY: just allocated by this thread.
                    unsafe { pmm.free(p, Order(0)) };
                }
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
    assert_eq!(pmm.allocated_pages(), 0);
    assert_eq!(pmm.free_pages(), n_pages);
    // SAFETY: all threads joined; sole accessor.
    unsafe { pmm.audit() };
}

#[test]
fn concurrent_unique_pfns_no_overlap() {
    // Each thread allocs a batch, holds them, threads compare for overlap.
    let n_pages = 1024u64;
    let pmm = Arc::new(build(n_pages));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let pmm = Arc::clone(&pmm);
        handles.push(thread::spawn(move || {
            let mut local: Vec<(u64, u8)> = Vec::new();
            for _ in 0..50 {
                let o = (local.len() % 3) as u8;
                if let Ok(p) = pmm.alloc(Order(o)) {
                    local.push((p.0, o));
                }
            }
            local
        }));
    }
    let mut all: Vec<(u64, u8)> = Vec::new();
    for h in handles { all.extend(h.join().unwrap()); }
    // Verify no two outstanding ranges overlap.
    for i in 0..all.len() {
        let (p, o) = all[i];
        let span = 1u64 << o;
        for j in (i + 1)..all.len() {
            let (q, qo) = all[j];
            let qspan = 1u64 << qo;
            let overlap = !(q + qspan <= p || p + span <= q);
            assert!(!overlap, "overlap pfn {}+{} vs {}+{}", p, span, q, qspan);
        }
    }
    // Free everything.
    for (p, o) in all {
        // SAFETY: each (p,o) was just returned by Pmm::alloc.
        unsafe { pmm.free(Pfn(p), Order(o)) };
    }
    assert_eq!(pmm.free_pages(), n_pages);
    // SAFETY: all threads joined.
    unsafe { pmm.audit() };
}

// ---------------------------------------------------------------------------
// (11) Proptest oracle. BTreeMap-of-outstanding agreement per `10§9`.
// ---------------------------------------------------------------------------

struct Oracle {
    outstanding: BTreeMap<u64, u8>,  // pfn → order
    total_pfns: u64,
}

impl Oracle {
    fn new(total_pfns: u64) -> Self {
        Self { outstanding: BTreeMap::new(), total_pfns }
    }
    fn allocated(&self) -> u64 {
        self.outstanding.values().map(|o| 1u64 << o).sum()
    }
    fn free(&self) -> u64 { self.total_pfns - self.allocated() }
    fn overlaps(&self, p: u64, o: u8) -> bool {
        let span = 1u64 << o;
        for (&q, &qo) in self.outstanding.iter() {
            let qspan = 1u64 << qo;
            if !(q + qspan <= p || p + span <= q) { return true; }
        }
        false
    }
}

#[derive(Debug, Clone)]
enum Op { Alloc(u8), FreeNth(usize), Reserve(u32, u32) }

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0u8..=4u8).prop_map(Op::Alloc),
        4 => (0usize..64).prop_map(Op::FreeNth),
        1 => (0u32..1024, 0u32..16).prop_map(|(s, l)| Op::Reserve(s, l)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 200, max_shrink_iters: 1024, .. ProptestConfig::default()
    })]

    #[test]
    fn oracle_agreement(ops in proptest::collection::vec(op_strategy(), 1..600)) {
        let n = 1024u64;
        let pmm = build(n);
        let mut oracle = Oracle::new(n);

        for op in ops {
            match op {
                Op::Alloc(o) => {
                    match pmm.alloc(Order(o)) {
                        Ok(p) => {
                            prop_assert_eq!(p.0 & ((1u64 << o) - 1), 0);  // I4
                            prop_assert!(p.0 < n);
                            prop_assert!(!oracle.outstanding.contains_key(&p.0));
                            prop_assert!(!oracle.overlaps(p.0, o), "alloc overlap");
                            oracle.outstanding.insert(p.0, o);
                        }
                        Err(Error::NoMem) => { /* allocator may legitimately fail */ }
                        Err(e) => prop_assert!(false, "unexpected alloc err {:?}", e),
                    }
                }
                Op::FreeNth(n_idx) => {
                    let keys: Vec<(u64, u8)> = oracle.outstanding.iter().map(|(k, v)| (*k, *v)).collect();
                    if keys.is_empty() { continue; }
                    let (p, o) = keys[n_idx % keys.len()];
                    // SAFETY: (p, o) was returned by pmm.alloc and is still oracle-tracked.
                    unsafe { pmm.free(Pfn(p), Order(o)) };
                    oracle.outstanding.remove(&p);
                }
                Op::Reserve(_s, _l) => {
                    // reserve_early would race with alloc/free state in
                    // unpredictable ways; we keep it out of the oracle
                    // op stream and test it separately above.
                }
            }
            prop_assert_eq!(pmm.free_pages(), oracle.free());
            prop_assert_eq!(pmm.allocated_pages(), oracle.allocated());
            // SAFETY: hosted single-thread; audit takes its own lock.
            unsafe { pmm.audit() };
        }
        // Free everything left, expect full recovery.
        let leftover: Vec<(u64, u8)> = oracle.outstanding.iter().map(|(k,v)| (*k,*v)).collect();
        for (p, o) in leftover {
            // SAFETY: tracked outstanding by oracle ⇒ valid pfn at order.
            unsafe { pmm.free(Pfn(p), Order(o)) };
        }
        prop_assert_eq!(pmm.free_pages(), n);
        // SAFETY: hosted single-thread.
        unsafe { pmm.audit() };
    }

    #[test]
    fn aligned_pfn_invariant(o in 0u8..=8u8, n_pre in 0u32..200) {
        let pmm = build(2048);
        for _ in 0..n_pre { let _ = pmm.alloc(Order(0)); }
        if let Ok(p) = pmm.alloc(Order(o)) {
            prop_assert_eq!(p.0 & ((1u64 << o) - 1), 0);
        }
    }
}
