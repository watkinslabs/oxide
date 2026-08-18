use super::*;
use crate::zone::ZoneType;

fn cached_pages(pmm: &Pmm<HostedBacking>) -> u64 {
    pmm.pcp_cached_pages().into_iter().sum()
}

#[test]
fn order_zero_free_reuses_the_local_pageset() {
    let pmm = build(64);
    let p = pmm.alloc(Order(0)).unwrap();
    // SAFETY: p was returned by this PMM and remains this test's allocation.
    unsafe { pmm.free(p, Order(0)) };
    assert_eq!(cached_pages(&pmm), 1, "the free must enter the local pageset");

    let q = pmm.alloc(Order(0)).unwrap();
    assert_eq!(q, p, "the local pageset must satisfy the next order-0 allocation");
    assert_eq!(cached_pages(&pmm), 0);
    // SAFETY: q is the one outstanding allocation in this test.
    unsafe { pmm.free(q, Order(0)) };
    // SAFETY: single-threaded test with no allocator transition in flight.
    unsafe { pmm.audit() };
}

#[test]
fn pageset_free_above_high_drains_one_batch() {
    let pmm = build(16);
    let held: Vec<Pfn> = (0..5).map(|_| pmm.alloc(Order(0)).unwrap()).collect();
    for pfn in held {
        // SAFETY: each pfn is an allocation returned immediately above.
        unsafe { pmm.free(pfn, Order(0)) };
    }

    let high = pmm.pcp_high_pages(ZoneType::Normal);
    assert_eq!(high, 4, "small zones retain four order-0 refill slots");
    assert_eq!(cached_pages(&pmm), high, "the fifth free must drain a batch");
    // SAFETY: single-threaded test with no allocator transition in flight.
    unsafe { pmm.audit() };
}

#[test]
fn high_order_miss_drains_pagesets_before_failing() {
    let pmm = build(8);
    let held: Vec<Pfn> = (0..8).map(|_| pmm.alloc(Order(0)).unwrap()).collect();
    for pfn in held {
        // SAFETY: each pfn is an allocation returned immediately above.
        unsafe { pmm.free(pfn, Order(0)) };
    }
    assert_eq!(cached_pages(&pmm), 4);

    let block = pmm.alloc(Order(3)).expect("cached pages must be drained and coalesced");
    assert_eq!(cached_pages(&pmm), 0);
    // SAFETY: block is the order-3 allocation returned immediately above.
    unsafe { pmm.free(block, Order(3)) };
    // SAFETY: single-threaded test with no allocator transition in flight.
    unsafe { pmm.audit() };
}

#[test]
#[should_panic(expected = "per-cpu pageset")]
fn double_free_while_cached_is_rejected_by_pageset_bitmap() {
    let pmm = build(64);
    let p = pmm.alloc(Order(0)).unwrap();
    // SAFETY: the first call is the unique legitimate free.
    unsafe { pmm.free(p, Order(0)) };
    // SAFETY: deliberately invalid repeat free to prove the pageset detector.
    unsafe { pmm.free(p, Order(0)) };
}
