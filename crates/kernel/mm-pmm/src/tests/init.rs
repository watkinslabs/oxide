use super::*;

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
    assert_eq!(Pmm::<HostedBacking>::init(b, &[]).err(), Some(Error::OutOfRange));
}

#[test]
fn init_overflow_start_plus_len_returns_err() {
    let b = HostedBacking::new(64);
    let r = [UsableRegion { start: Pfn(u64::MAX - 5), len_pfn: 100 }];
    assert_eq!(Pmm::<HostedBacking>::init(b, &r).err(), Some(Error::OutOfRange));
}

#[test]
fn init_overflow_total_returns_err() {
    let b = HostedBacking::new(64);
    let r = [
        UsableRegion { start: Pfn(0),                 len_pfn: u64::MAX / 2 + 1 },
        UsableRegion { start: Pfn(u64::MAX / 2 + 2), len_pfn: u64::MAX / 2 + 1 },
    ];
    // Sum overflows even before we check overlap.
    assert!(matches!(Pmm::<HostedBacking>::init(b, &r).err(), Some(Error::OutOfRange) | Some(Error::Overlap)));
}

#[test]
fn init_overlapping_regions_returns_overlap() {
    let b = HostedBacking::new(256);
    let r = [
        UsableRegion { start: Pfn(0),   len_pfn: 200 },
        UsableRegion { start: Pfn(100), len_pfn: 100 },  // overlaps [100..200) of first
    ];
    assert_eq!(Pmm::<HostedBacking>::init(b, &r).err(), Some(Error::Overlap));
}

#[test]
fn init_adjacent_regions_ok() {
    // touching but not overlapping
    let b = HostedBacking::new(256);
    let r = [
        UsableRegion { start: Pfn(0),   len_pfn: 100 },
        UsableRegion { start: Pfn(100), len_pfn: 100 },
    ];
    let pmm = Pmm::<HostedBacking>::init(b, &r).unwrap();
    assert_eq!(pmm.free_pages(), 200);
}

#[test]
fn init_zero_length_region_skipped() {
    let b = HostedBacking::new(64);
    let r = [
        UsableRegion { start: Pfn(0), len_pfn: 0 },
        UsableRegion { start: Pfn(0), len_pfn: 64 },
    ];
    let pmm = Pmm::<HostedBacking>::init(b, &r).unwrap();
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
    let pmm = Pmm::<HostedBacking>::init(b, &r).unwrap();
    // SAFETY: hosted single-thread; audit takes its own lock.
    unsafe { pmm.audit() };
    assert_eq!(pmm.free_pages(), 512);
}

#[test]
fn seed_only_writes_the_free_block_head() {
    let fill = 0xa5;
    let backing = HostedBacking::filled(8, fill);
    let pmm = Pmm::<HostedBacking>::init(
        backing,
        &[UsableRegion { start: Pfn(0), len_pfn: 8 }],
    )
    .unwrap();

    // One order-3 block is seeded.  Its head gains the intrusive FreeNode;
    // the seven tails must remain untouched until a caller allocates them.
    for pfn in 1..8 {
        // SAFETY: this hosted backing remains live for the test and page_ptr
        // names the first byte of the untouched tail page.
        let tail = unsafe { pmm.page_ptr(Pfn(pfn)) };
        assert_eq!(unsafe { core::ptr::read(tail) }, fill, "tail pfn {pfn} was touched at seed");
    }
    // SAFETY: the head is a live free-list node and contains its poison word.
    let head = unsafe { pmm.page_ptr(Pfn(0)) };
    assert_eq!(unsafe { core::ptr::read_unaligned(head.cast::<u64>()) }, POISON_MAGIC);
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
