use super::*;
use std::time::{Duration, Instant};

const POOL_ORDER: u8 = 10;
const POOL_PAGES: u64 = 1 << POOL_ORDER;
const ROUNDS: u64 = 128;

fn describe(label: &str, order: u8, alloc: Duration, free: Duration, snap: PmmSnapshot) {
    std::println!("RENDER_PERF pmm={} order={} rounds={} alloc_ns/op={} free_ns/op={} zero_bytes={} alloc_events={} free_events={}",
        label, order, ROUNDS, alloc.as_nanos() / ROUNDS as u128,
        free.as_nanos() / ROUNDS as u128, snap.alloc_event_pages * PAGE as u64,
        snap.alloc_events, snap.free_events);
}

fn verify_and_dirty(pmm: &Pmm<HostedBacking>, pfn: Pfn, order: u8) {
    // SAFETY: this benchmark exclusively owns the complete live allocation.
    let bytes = unsafe { core::slice::from_raw_parts_mut(pmm.page_ptr(pfn), PAGE << order) };
    assert!(bytes.iter().all(|&byte| byte == 0), "allocation did not zero its entire span");
    bytes.fill(0x5a);
    core::hint::black_box(bytes);
}

#[test]
#[ignore = "bounded optimized hosted benchmark; run explicitly with --release --ignored --nocapture"]
fn render_perf_buddy_split_coalesce_and_zero() {
    for order in [1, 4, 9, 10] {
        let pmm = build(POOL_PAGES);
        let initial = pmm.free_orders();
        assert_eq!(initial[POOL_ORDER as usize], 1);
        let mut alloc = Duration::ZERO;
        let mut free = Duration::ZERO;
        for _ in 0..ROUNDS {
            let start = Instant::now();
            let pfn = core::hint::black_box(pmm.alloc(Order(order)).unwrap());
            alloc += start.elapsed();
            // The actual free-order snapshot proves each allocation split the
            // one initial block down through precisely these intermediate orders.
            let split = pmm.free_orders();
            for o in 0..ORDERS {
                assert_eq!(split[o], u64::from(o >= order as usize && o < POOL_ORDER as usize));
            }
            verify_and_dirty(&pmm, pfn, order);
            let start = Instant::now();
            // SAFETY: pfn/order is the unique live allocation obtained above.
            unsafe { pmm.free(pfn, Order(order)); }
            free += start.elapsed();
            assert_eq!(pmm.free_orders(), initial, "free did not fully coalesce");
        }
        let snap = pmm.snapshot();
        assert_eq!(snap.alloc_events, ROUNDS);
        assert_eq!(snap.free_events, ROUNDS);
        assert_eq!(snap.alloc_event_pages, ROUNDS << order);
        assert_eq!(snap.allocated_pages, 0);
        // SAFETY: all benchmark allocations have been returned; no concurrent access.
        unsafe { pmm.audit(); }
        describe("split-coalesce", order, alloc, free, snap);
        std::println!("RENDER_PERF splits={} coalesces={} (verified via free-order snapshots)",
            ROUNDS * u64::from(POOL_ORDER - order), ROUNDS * u64::from(POOL_ORDER - order));
    }
}

#[test]
#[ignore = "bounded optimized hosted benchmark; run explicitly with --release --ignored --nocapture"]
fn render_perf_buddy_order_zero_pageset() {
    let pmm = build(POOL_PAGES);
    let mut alloc = Duration::ZERO;
    let mut free = Duration::ZERO;
    for _ in 0..ROUNDS {
        let start = Instant::now();
        let pfn = core::hint::black_box(pmm.alloc(Order(0)).unwrap());
        alloc += start.elapsed();
        verify_and_dirty(&pmm, pfn, 0);
        let start = Instant::now();
        // SAFETY: pfn is the unique live order-zero allocation obtained above.
        unsafe { pmm.free(pfn, Order(0)); }
        free += start.elapsed();
    }
    let snap = pmm.snapshot();
    assert_eq!(snap.alloc_events, ROUNDS);
    assert_eq!(snap.free_events, ROUNDS);
    assert_eq!(snap.free_pages, POOL_PAGES);
    describe("pcp-including-first-refill", 0, alloc, free, snap);
    pmm.drain_pcp_for_test();
    assert_eq!(pmm.free_orders()[POOL_ORDER as usize], 1);
    // SAFETY: the serial benchmark returned and drained all allocations.
    unsafe { pmm.audit(); }
}
