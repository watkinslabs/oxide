// Provenance: a bounded (bus-master) allocation is an ordinary allocation
// with a zone bound. It is therefore held to the same per-zone watermark as
// every other request, it enters the same reclaim/kill retry when the fast
// path finds nothing, and it never returns a block outside its bound even
// when satisfying it means falling to a narrower zone.
//
// These tests exist because the bounded path used to walk the free lists
// itself: it took the first block that fitted the address regardless of the
// zone's marks, and reported exhaustion without ever entering the slowpath.

use super::*;

const POOL: u64 = 8192;
const DMA_END: u64 = 2048;
const DMA32_END: u64 = POOL;

fn limits(dma_end: u64, dma32_end: u64) -> crate::zone::ZoneLimits {
    crate::zone::ZoneLimits { dma_end_pfn: dma_end, dma32_end_pfn: dma32_end, movable_start_pfn: None }
}

/// Pool split across DMA and DMA32 so a bound at the DMA top names one zone.
fn split_pool() -> Pmm<HostedBacking> {
    let b = HostedBacking::new(POOL);
    Pmm::<HostedBacking>::init_zoned(b, &[UsableRegion { start: Pfn(0), len_pfn: POOL }], Some(limits(DMA_END, DMA32_END))).unwrap()
}

/// Take order-0 pages under `bound` until the allocator refuses, and report
/// what the bounded zone kept back — the whole-system total says nothing
/// here, because the zones the bound excludes are never touched.
/// Allocations are deliberately never returned.
fn drain_below(p: &Pmm<HostedBacking>, bound: u64) -> u64 {
    let mut taken = 0u64;
    while let Ok(pfn) = p.alloc_below(Order(0), Pfn(bound)) {
        assert!(pfn.0 < bound, "allocator escaped its bound: pfn {} >= {bound}", pfn.0);
        taken += 1;
        assert!(taken <= POOL, "drain never terminated");
    }
    p.zone_snapshot()[0].free_pages
}

#[test]
fn a_bounded_allocation_is_held_to_the_zones_watermark() {
    let _right = crate::watermark::PublishGuard::acquire();
    let bare = split_pool();
    let left_bare = drain_below(&bare, DMA_END);

    let gated = split_pool();
    gated.refresh_watermarks(crate::watermark::WatermarkTunables::default());
    let mark = gated.zone_snapshot()[0].wmark.min;
    let left_gated = drain_below(&gated, DMA_END);

    assert!(mark > 0, "the fixture derived no minimum, so this test cannot fail");
    assert!(left_gated > left_bare,
        "the bounded path ignores the gate: unmarked allocator left {left_bare} pages, marked one left {left_gated}");
}

#[test]
fn a_bounded_allocation_that_finds_nothing_reaches_the_slowpath_mark() {
    let _right = crate::watermark::PublishGuard::acquire();
    let p = split_pool();
    p.refresh_watermarks(crate::watermark::WatermarkTunables::default());
    let z = p.zone_snapshot()[0].wmark;
    assert!(z.low > z.min, "the fixture's marks are indistinguishable, so this test cannot fail");
    let left = drain_below(&p, DMA_END);

    // Stopping at the low mark would mean only the fast path ever ran. The
    // request has to be re-offered against the min mark before exhaustion is
    // the answer, which is what the slowpath does first.
    assert!(left < z.low,
        "the bounded path stopped at the low mark ({left} left, low {}), so it never entered the slowpath", z.low);
    assert!(left > 0, "the gate held nothing back at all, so the marks are not being read");
}

#[test]
fn a_block_outside_the_bound_is_returned_and_a_narrower_zone_tried() {
    // The bound falls above every addressable zone's top, so it names no zone
    // and the first attempt is an ordinary allocation — which this fixture
    // answers from NORMAL, above the bound. Only the next rung down can serve
    // the request, and only DMA32 holds anything: an answer from the DMA zone
    // is impossible here, so a ladder that skipped a rung would fail outright
    // rather than quietly produce the same address.
    const N: u64 = 1024;
    const BOUND: u64 = 512;
    let b = HostedBacking::new(N);
    let p = Pmm::<HostedBacking>::init_zoned(
        b,
        &[UsableRegion { start: Pfn(64), len_pfn: 192 }, UsableRegion { start: Pfn(800), len_pfn: 224 }],
        Some(limits(64, 256)),
    ).unwrap();
    let z = p.zone_snapshot();
    assert_eq!(z[0].managed_pages, 0, "the fixture left the DMA zone able to answer, so a skipped rung would pass");
    assert_eq!(z[1].managed_pages, 192, "the fixture put nothing in the zone that has to answer");
    assert!(z[2].managed_pages > 0, "the fixture put nothing above the bound");
    assert_eq!(crate::zone::gfp_for_pfn_limit(&crate::zone::ZoneLayout::new(limits(64, 256), N), BOUND), 0,
        "the fixture's bound names a zone, so the first attempt never overshoots");

    let pfn = p.alloc_below(Order(0), Pfn(BOUND)).expect("the DMA32 zone can serve this");
    assert!(pfn.0 < BOUND, "allocator escaped its bound: {}", pfn.0);
    assert!((64..256).contains(&pfn.0), "the answer did not come from the narrowed zone: {}", pfn.0);
    // SAFETY: `pfn` is the order-0 allocation returned immediately above.
    unsafe { p.free(pfn, Order(0)); }
    // SAFETY: the allocation/free transition above completed synchronously.
    unsafe { p.audit(); }
}

#[test]
fn a_bound_no_populated_zone_can_meet_fails_rather_than_escaping_it() {
    const N: u64 = 1024;
    let b = HostedBacking::new(N);
    let p = Pmm::<HostedBacking>::init_zoned(
        b,
        &[UsableRegion { start: Pfn(800), len_pfn: 224 }],
        Some(limits(64, 256)),
    ).unwrap();
    // Memory exists — 224 pages of it — but none of it is addressable under
    // the bound, and handing out the nearest block would be worse than
    // failing: the device would write somewhere it cannot reach.
    assert!(p.free_pages() > 0, "the fixture owns no memory, so this test cannot fail");
    assert_eq!(p.alloc_below(Order(0), Pfn(32)), Err(Error::NoMem));
    assert_eq!(p.alloc_below(Order(3), Pfn(256)), Err(Error::NoMem));
}
