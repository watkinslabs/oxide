use super::*;

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
    for k in 0..(1u64 << 2) {
        // SAFETY: PMM-owned freshly allocated page; backing accessed
        // lock-free per Pmm's lock-free page_ptr invariant.
        let ptr = unsafe { pmm.page_ptr(Pfn(p.0 + k)) };
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
    // SAFETY: corrupting page 0 to exercise poison detection on next alloc.
    let ptr = unsafe { pmm.page_ptr(Pfn(0)) };
    // SAFETY: writing into a free page's poison u64; test-only.
    unsafe { core::ptr::write_unaligned(ptr as *mut u64, 0) };
    for _ in 0..64 { let _ = pmm.alloc(Order(0)).unwrap(); }
}

#[cfg(feature = "debug-watchdog")]
#[test]
fn watchdog_scans_poison_before_allocation_zeroes_page() {
    let pmm = build(1);
    let pfn = pmm.alloc(Order(0)).unwrap();
    // SAFETY: the test owns this one-page allocation.
    let page = unsafe { pmm.page_ptr(pfn) };
    // SAFETY: page points to the complete caller-owned allocation.
    unsafe { core::ptr::write_bytes(page, 0xAA, PAGE) };
    // SAFETY: pfn is the live order-0 allocation returned above.
    unsafe { pmm.free(pfn, Order(0)) };
    // SAFETY: deliberately emulate a stale write into the free page body.
    unsafe { core::ptr::write_volatile(page.add(197), 0x31) };

    assert_eq!(crate::buddy::take_test_mismatch(), None);
    let allocated = pmm.alloc(Order(0)).unwrap();
    assert_eq!(allocated, pfn);
    assert_eq!(crate::buddy::take_test_mismatch(), Some(197));
    // SAFETY: allocation returned ownership and alloc_inner zeroed the page.
    assert_eq!(unsafe { core::ptr::read(page.add(197)) }, 0);
}
