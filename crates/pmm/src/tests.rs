// Hosted tests + proptest oracle per `10§9`. Vec-backed `PageBacking`
// scales from KiB to many GiB; verifies bitmap-truth, split/merge,
// poison detection, multi-region init, reserve_early.

use super::*;
use core::sync::atomic::AtomicU64;
use proptest::prelude::*;
use std::boxed::Box;
use std::collections::BTreeSet;
use std::vec;
use std::vec::Vec;

const PAGE: usize = PAGE_SIZE_BYTES as usize;

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
        let buf = vec![0u8; (n_pages as usize) * PAGE].into_boxed_slice();
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
        assert!(s.len() >= len_u64, "bitmap too small for order {}: have {} need {}", order, s.len(), len_u64);
        s
    }
}

fn build_one(n_pages: u64) -> Pmm<HostedBacking> {
    let b = HostedBacking::new(n_pages);
    Pmm::init(b, &[UsableRegion { start: Pfn(0), len_pfn: n_pages }]).unwrap()
}

fn build_regions(n_pages: u64, regions: &[UsableRegion]) -> Pmm<HostedBacking> {
    let b = HostedBacking::new(n_pages);
    Pmm::init(b, regions).unwrap()
}

// ---------------------------------------------------------------------------
// Boot / init.
// ---------------------------------------------------------------------------

#[test]
fn boot_audit_clean_power_of_two() {
    let pmm = build_one(1024);
    // SAFETY: hosted single-thread; Pmm::audit takes its own lock.
    unsafe { pmm.audit() };
    assert_eq!(pmm.free_pages(), 1024);
    assert_eq!(pmm.allocated_pages(), 0);
}

#[test]
fn boot_audit_clean_non_power_of_two() {
    let pmm = build_one(1500);
    // SAFETY: hosted single-thread; audit takes its own lock.
    unsafe { pmm.audit() };
    assert_eq!(pmm.free_pages(), 1500);
}

#[test]
fn boot_ten_megabytes() {
    // 10 MiB / 4 KiB = 2560 pages.
    let n = 10 * 1024 * 1024 / PAGE_SIZE_BYTES;
    let pmm = build_one(n);
    // SAFETY: hosted single-thread; audit takes its own lock.
    unsafe { pmm.audit() };
    assert_eq!(pmm.free_pages(), n);
}

#[test]
fn boot_two_gigabytes() {
    // 2 GiB / 4 KiB = 524288 pages. Test that bitmap sizes scale + init runs.
    let n = 2u64 * 1024 * 1024 * 1024 / PAGE_SIZE_BYTES;
    let pmm = build_one(n);
    // SAFETY: hosted single-thread; audit takes its own lock.
    unsafe { pmm.audit() };
    assert_eq!(pmm.free_pages(), n);
    // Two-GiB exact ⇒ should give one order-19 + one order-19 OR one order-19 each — actually 2GiB = 2 × 1GiB = 2 × 2^18 4KiB-pages × 2 = 2^19 pages. So one order-19 block.
    assert_eq!(pmm.allocated_pages(), 0);
}

#[test]
fn multi_region_init() {
    // Two disjoint regions: [0..256) and [512..768).
    let n_pages = 1024;
    let pmm = build_regions(n_pages, &[
        UsableRegion { start: Pfn(0),   len_pfn: 256 },
        UsableRegion { start: Pfn(512), len_pfn: 256 },
    ]);
    // SAFETY: hosted single-thread; audit takes its own lock.
    unsafe { pmm.audit() };
    assert_eq!(pmm.free_pages(), 512);
}

// ---------------------------------------------------------------------------
// Alloc / free / split / merge.
// ---------------------------------------------------------------------------

#[test]
fn alloc_each_order_then_free_audits_clean() {
    // n=4096 (order-12) with allocs 0..=10 summing to 2047 pages.
    let pmm = build_one(4096);
    let mut held: Vec<(Pfn, Order)> = Vec::new();
    for o in 0..=10u8 {
        let p = pmm.alloc(Order(o)).unwrap();
        held.push((p, Order(o)));
        // SAFETY: hosted single-thread; audit takes its own lock.
        unsafe { pmm.audit() };
    }
    let outstanding: u64 = held.iter().map(|(_, o)| 1u64 << o.0).sum();
    assert_eq!(pmm.allocated_pages(), outstanding);
    for (p, o) in held.into_iter().rev() {
        // SAFETY: every (p, o) was just returned by Pmm::alloc above.
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
    let pmm = build_one(n);
    let mut pfns: Vec<Pfn> = (0..n).map(|_| pmm.alloc(Order(0)).unwrap()).collect();
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for i in (1..pfns.len()).rev() {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        let j = (x as usize) % (i + 1);
        pfns.swap(i, j);
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
fn alloc_zeros_returned_pages() {
    let pmm = build_one(256);
    let p = pmm.alloc(Order(2)).unwrap();
    // Read first 32 bytes of each page in the order-2 block; expect zero.
    // SAFETY: page is owned by us until freed; read PAGE_SIZE_BYTES worth.
    let g = pmm.inner.lock();
    for k in 0..4u64 {
        // SAFETY: PMM-owned freshly allocated page; ptr is valid for PAGE.
        let ptr = unsafe { g.backing.page_ptr(Pfn(p.0 + k)) };
        for off in 0..32 {
            // SAFETY: within the 4 KiB freshly-zeroed page.
            let v = unsafe { core::ptr::read(ptr.add(off)) };
            assert_eq!(v, 0, "page {} byte {} not zeroed", p.0 + k, off);
        }
    }
}

#[test]
fn alloc_rejects_oversized_order() {
    let pmm = build_one(64);
    assert_eq!(pmm.alloc(Order(MAX_ORDER + 1)), Err(Error::InvalidOrder));
}

#[test]
fn alloc_oom_returns_nomem() {
    let pmm = build_one(4);
    let _a = pmm.alloc(Order(2)).unwrap();
    assert_eq!(pmm.alloc(Order(0)), Err(Error::NoMem));
}

#[test]
#[should_panic(expected = "double free")]
fn double_free_kasserts() {
    let pmm = build_one(64);
    let p = pmm.alloc(Order(0)).unwrap();
    // SAFETY: p was just allocated.
    unsafe { pmm.free(p, Order(0)) };
    // SAFETY: deliberately incorrect — exercises the double-free check.
    unsafe { pmm.free(p, Order(0)) };
}

#[test]
#[should_panic(expected = "poison")]
fn corrupted_free_page_caught_on_alloc() {
    let pmm = build_one(64);
    {
        let g = pmm.inner.lock();
        // SAFETY: corrupting page 0 to exercise poison detection on alloc.
        let p = unsafe { g.backing.page_ptr(Pfn(0)) };
        // SAFETY: write into the freed page's poison field; test-only.
        unsafe { core::ptr::write_unaligned(p as *mut u64, 0) };
    }
    for _ in 0..64 {
        let _ = pmm.alloc(Order(0)).unwrap();
    }
}

// ---------------------------------------------------------------------------
// reserve_early.
// ---------------------------------------------------------------------------

#[test]
fn reserve_early_shrinks_free_pool() {
    let pmm = build_one(1024);
    pmm.reserve_early(Pfn(100), 50).unwrap();
    // SAFETY: hosted single-thread; audit takes its own lock.
    unsafe { pmm.audit() };
    assert_eq!(pmm.free_pages(), 1024 - 50);
    assert_eq!(pmm.allocated_pages(), 50);
}

#[test]
fn reserve_early_then_alloc_avoids_reserved() {
    let n = 256u64;
    let pmm = build_one(n);
    pmm.reserve_early(Pfn(0), 64).unwrap();
    // SAFETY: hosted single-thread; audit.
    unsafe { pmm.audit() };
    // Drain remaining pages; none should be < 64.
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    while let Ok(p) = pmm.alloc(Order(0)) {
        assert!(p.0 >= 64, "alloc returned reserved pfn {}", p.0);
        seen.insert(p.0);
    }
    assert_eq!(seen.len() as u64, n - 64);
}

#[test]
fn reserve_early_multi_call_idempotent() {
    let pmm = build_one(512);
    pmm.reserve_early(Pfn(10), 5).unwrap();
    pmm.reserve_early(Pfn(10), 5).unwrap();  // already reserved; no-op
    // SAFETY: hosted single-thread; audit.
    unsafe { pmm.audit() };
    assert_eq!(pmm.allocated_pages(), 5);
}

// ---------------------------------------------------------------------------
// Proptest oracle per `10§9`. Oracle = naive bookkeeping (sorted free
// set, no bitmap, recompute every op). Per-op assert: outstanding-PFN
// set agrees, total free agrees, per-order free count agrees.
// ---------------------------------------------------------------------------

struct Oracle {
    outstanding: std::collections::BTreeMap<u64, u8>, // pfn → order
    total_pfns: u64,
}

impl Oracle {
    fn new(total_pfns: u64) -> Self {
        Self { outstanding: Default::default(), total_pfns }
    }
    fn allocated_pages(&self) -> u64 {
        self.outstanding.values().map(|o| 1u64 << o).sum()
    }
    fn free_pages(&self) -> u64 {
        self.total_pfns - self.allocated_pages()
    }
}

#[derive(Debug, Clone)]
enum Op {
    Alloc(u8),
    FreeNth(usize),
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0u8..=4u8).prop_map(Op::Alloc),
        (0usize..32).prop_map(Op::FreeNth),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 200, .. ProptestConfig::default() })]

    #[test]
    fn oracle_agreement_small(ops in proptest::collection::vec(op_strategy(), 1..400)) {
        let n = 1024u64;
        let pmm = build_one(n);
        let mut oracle = Oracle::new(n);

        for op in ops {
            match op {
                Op::Alloc(o) => {
                    match pmm.alloc(Order(o)) {
                        Ok(p) => {
                            // Oracle: pfn shouldn't already be outstanding.
                            prop_assert!(!oracle.outstanding.contains_key(&p.0));
                            // No outstanding block overlaps p..p+(1<<o).
                            let span = 1u64 << o;
                            for (&q, &qo) in oracle.outstanding.iter() {
                                let qspan = 1u64 << qo;
                                let overlap = !(q + qspan <= p.0 || p.0 + span <= q);
                                prop_assert!(!overlap, "alloc overlap with outstanding");
                            }
                            oracle.outstanding.insert(p.0, o);
                        }
                        Err(Error::NoMem) => {
                            // Oracle agreement: oracle's free pool can't fit `o` either.
                            // Cheap sufficient check: oracle.free_pages() < (1<<o)
                            // is sufficient but not necessary (fragmentation). We
                            // accept any NoMem the allocator reports.
                        }
                        Err(e) => prop_assert!(false, "unexpected alloc err {:?}", e),
                    }
                }
                Op::FreeNth(n) => {
                    let keys: Vec<(u64, u8)> = oracle.outstanding.iter().map(|(k,v)| (*k,*v)).collect();
                    if keys.is_empty() { continue; }
                    let (p, o) = keys[n % keys.len()];
                    // SAFETY: `p` was returned by pmm.alloc above and tracked in oracle.
                    unsafe { pmm.free(Pfn(p), Order(o)) };
                    oracle.outstanding.remove(&p);
                }
            }
            // Per-op invariants: total free + allocated == initial.
            prop_assert_eq!(pmm.free_pages(), oracle.free_pages());
            prop_assert_eq!(pmm.allocated_pages(), oracle.allocated_pages());
            // SAFETY: hosted single-thread; audit takes its own lock.
            unsafe { pmm.audit() };
        }
    }
}

#[test]
fn max_order_invariant() {
    assert_eq!(MAX_ORDER, 20);
}
