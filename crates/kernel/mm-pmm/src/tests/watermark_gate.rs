// Provenance: the per-zone watermarks the allocation gate reads have exactly
// one producer, and driving it is what makes the gate live. Before the
// producer runs every zone's marks are zero, so the gate can only ever be
// cleared; after it, a drain stops with the marks' worth of pages still free.
// These tests exist because the array was reachable from the allocator and
// nothing computed it — a gate that is consulted but never populated reads as
// policy and behaves as none.

use super::*;
use crate::watermark::{WatermarkTunables, ZoneWatermarks};

/// Pool large enough that the arch's zone split populates more than one zone
/// and the derived marks land well clear of zero.
const POOL_PAGES: u64 = 8192;

/// Take every order-0 page the allocator will part with, and report what it
/// refused to give up. Allocations are deliberately never returned.
fn drain(p: &Pmm<HostedBacking>) -> u64 {
    let mut taken = 0u64;
    while p.alloc(Order(0)).is_ok() { taken += 1; assert!(taken <= POOL_PAGES, "drain never terminated"); }
    p.free_pages()
}

#[test]
fn the_marks_are_zero_until_the_refresh_produces_them() {
    let _right = crate::watermark::PublishGuard::acquire();
    let p = build(POOL_PAGES);
    for z in p.zone_snapshot() {
        assert_eq!(z.wmark, ZoneWatermarks::default(), "a freshly built zone carries no marks: {z:?}");
    }
    p.refresh_watermarks(WatermarkTunables::default());
    let after = p.zone_snapshot();
    let populated = after.iter().filter(|z| z.managed_pages > 0).count();
    assert!(populated > 0, "the fixture populated no zone at all");
    for z in after.iter().filter(|z| z.managed_pages > 0) {
        assert!(z.wmark.min > 0, "populated zone left without a minimum: {z:?}");
        assert!(z.wmark.low > z.wmark.min && z.wmark.high > z.wmark.low, "marks out of order: {z:?}");
    }
    // An unpopulated slot is not owed a reserve it can never hold back.
    for z in after.iter().filter(|z| z.managed_pages == 0) {
        assert_eq!(z.wmark, ZoneWatermarks::default(), "empty zone given marks: {z:?}");
    }
}

#[test]
fn a_zones_share_of_the_minimum_follows_the_pages_it_manages() {
    let _right = crate::watermark::PublishGuard::acquire();
    let p = build(POOL_PAGES);
    p.refresh_watermarks(WatermarkTunables::default());
    let z = p.zone_snapshot();
    for a in z.iter() {
        for b in z.iter() {
            if a.managed_pages > b.managed_pages { assert!(a.wmark.min >= b.wmark.min, "{a:?} vs {b:?}"); }
        }
    }
}

#[test]
fn the_gate_holds_pages_back_only_once_the_marks_exist() {
    let _right = crate::watermark::PublishGuard::acquire();
    let bare = build(POOL_PAGES);
    let left_bare = drain(&bare);

    let gated = build(POOL_PAGES);
    gated.refresh_watermarks(WatermarkTunables::default());
    let marks: u64 = gated.zone_snapshot().iter().map(|z| z.wmark.min).sum();
    let left_gated = drain(&gated);

    assert!(marks > 0, "the fixture derived no marks, so this test cannot fail");
    assert!(left_gated > left_bare,
        "the gate is inert: unmarked allocator left {left_bare} pages, marked one left {left_gated}");
}

#[test]
fn a_post_boot_reservation_re_derives_what_it_shrank() {
    let _right = crate::watermark::PublishGuard::acquire();
    let p = build(POOL_PAGES);
    p.refresh_watermarks(WatermarkTunables::default());
    let before = p.zone_snapshot();
    // Take a quarter of the pool permanently out of the allocator's hands,
    // the way a trampoline / crash-kernel / persistent-store reservation does
    // after the boot path has already published its thresholds.
    p.reserve_early(Pfn(0), POOL_PAGES / 4).unwrap();
    let after = p.zone_snapshot();

    let zi = (0..after.len()).find(|&i| before[i].managed_pages != after[i].managed_pages)
        .expect("the reservation changed no zone's managed count");
    assert!(after[zi].managed_pages < before[zi].managed_pages);
    assert!(after[zi].wmark.min < before[zi].wmark.min,
        "the mark still names memory the allocator no longer owns: {:?} -> {:?}", before[zi].wmark, after[zi].wmark);
    // A shrunken zone also owes a smaller share to the classes above it.
    let sum = |r: &[u64]| -> u64 { r.iter().sum() };
    assert!(sum(&after[zi].lowmem_reserve) <= sum(&before[zi].lowmem_reserve));
}

/// Fixture with the DMA boundary placed deliberately inside the pool, so the
/// two halves are each other's buddy at the next order up and an unguarded
/// coalesce would produce one block spanning both zones.
fn zoned(n_pages: u64, dma_end: u64) -> Pmm<HostedBacking> {
    let b = HostedBacking::new(n_pages);
    Pmm::<HostedBacking>::init_zoned(
        b,
        &[UsableRegion { start: Pfn(0), len_pfn: n_pages }],
        Some(crate::zone::ZoneLimits { dma_end_pfn: dma_end, dma32_end_pfn: n_pages, movable_start_pfn: None }),
    ).unwrap()
}

#[test]
fn a_free_block_never_merges_across_a_zone_boundary() {
    const N: u64 = 128;
    const BOUNDARY: u64 = 64;
    let p = zoned(N, BOUNDARY);
    let z = p.zone_snapshot();
    assert_eq!(z[0].managed_pages, BOUNDARY, "the fixture did not split the pool");
    assert_eq!(z[1].managed_pages, N - BOUNDARY, "the fixture did not split the pool");

    // Drain and return everything, which is the coalescing path: every buddy
    // pair in the pool is offered for merge, including the pair that meets at
    // the boundary.
    let mut held = std::vec::Vec::new();
    while let Ok(pfn) = p.alloc(Order(0)) { held.push(pfn); }
    assert_eq!(held.len() as u64, N, "the fixture did not hand out the whole pool");
    // SAFETY: every PFN here came from `alloc` above and is freed exactly once.
    for pfn in held { unsafe { p.free(pfn, Order(0)); } }

    // SAFETY: the alloc/free transitions above all completed synchronously.
    unsafe { p.audit(); }
    for (zi, s) in p.zone_snapshot().iter().enumerate() {
        let end = s.start_pfn + s.spanned_pages;
        for (o, n) in s.free_orders.iter().enumerate() {
            if *n == 0 { continue; }
            assert!((1u64 << o) <= s.spanned_pages,
                "zone {zi} holds an order-{o} block it cannot contain (span {}..{end})", s.start_pfn);
        }
    }
    assert_eq!(p.free_pages(), N, "coalescing lost pages");
}
