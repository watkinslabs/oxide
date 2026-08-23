use super::*;

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

#[test]
fn reserve_early_exact_is_atomic_when_a_page_is_already_owned() {
    let pmm = build(128);
    pmm.reserve_early(Pfn(20), 1).unwrap();
    assert_eq!(pmm.reserve_early_exact(Pfn(19), 3), Err(Error::Overlap));
    assert_eq!(pmm.allocated_pages(), 1);
    assert_eq!(pmm.free_pages(), 127);
    // SAFETY: hosted single-thread; audit.
    unsafe { pmm.audit() };
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

// A permanent boot reservation is exactly the difference between what the
// firmware map made usable in a zone and what the allocator ended up owning.
// Reporting one figure for both hides every hole a reservation punches.
#[test]
fn a_boot_reservation_separates_present_from_managed() {
    let n = 4096u64;
    let pmm = build(n);
    let before = pmm.zone_snapshot();
    for z in before.iter() { assert_eq!(z.present_pages, z.managed_pages, "nothing is reserved yet: {z:?}"); }

    const RESERVED: u64 = 64;
    pmm.reserve_early(Pfn(0), RESERVED).unwrap();
    let after = pmm.zone_snapshot();
    let reserved_zone = after.iter().position(|z| z.managed_pages != before[z.zone.index()].managed_pages)
        .expect("the reservation left some zone's managed count");
    let z = &after[reserved_zone];
    assert_eq!(z.present_pages, before[reserved_zone].present_pages, "a reservation does not unmake a present page");
    assert_eq!(z.managed_pages, z.present_pages - RESERVED, "the reserved pages left the managed count");
    // Every other zone is untouched by a reservation that did not reach it.
    for (i, z) in after.iter().enumerate() {
        if i == reserved_zone { continue; }
        assert_eq!(z.present_pages, z.managed_pages, "zone {i} was not reserved from: {z:?}");
    }
}
