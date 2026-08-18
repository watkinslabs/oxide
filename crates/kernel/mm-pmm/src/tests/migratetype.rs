use super::*;
use crate::zone::{GFP_HIGHMEM, GFP_MOVABLE, MigrateType, ZoneLimits, ZoneType};

fn normal_and_movable() -> Pmm<HostedBacking> {
    let backing = HostedBacking::new(4096);
    Pmm::<HostedBacking>::init_zoned(
        backing, &[UsableRegion { start: Pfn(0), len_pfn: 4096 }],
        Some(ZoneLimits { dma_end_pfn: 0, dma32_end_pfn: 0, movable_start_pfn: Some(2048) }),
    ).unwrap()
}

#[test]
fn movable_gfp_prefers_the_movable_zone_and_returns_to_its_own_type() {
    let pmm = normal_and_movable();
    let pfn = pmm.alloc_gfp(Order(0), GFP_HIGHMEM | GFP_MOVABLE).expect("movable tail has free pages");
    assert!(pfn.0 >= 2048, "movable GFP escaped the movable zone: {}", pfn.0);
    assert_eq!(pmm.pageblock_migratetype(pfn), MigrateType::Movable);
    // SAFETY: pfn is the allocation returned immediately above.
    unsafe { pmm.free(pfn, Order(0)); }
    let again = pmm.alloc_gfp(Order(0), GFP_HIGHMEM | GFP_MOVABLE).unwrap();
    assert_eq!(again, pfn, "movable PCP list did not retain its matching class");
    // SAFETY: again is the one live allocation.
    unsafe { pmm.free(again, Order(0)); }
    // SAFETY: no allocator transition is in flight in this hosted test.
    unsafe { pmm.audit(); }
}

#[test]
fn movable_fallback_claims_a_pageblock_before_reusing_an_unmovable_list() {
    let backing = HostedBacking::new(1024);
    let pmm = Pmm::<HostedBacking>::init_zoned(
        backing,
        &[UsableRegion { start: Pfn(0), len_pfn: 512 }, UsableRegion { start: Pfn(512), len_pfn: 512 }],
        Some(ZoneLimits {
            dma_end_pfn: 0,
            dma32_end_pfn: 0,
            movable_start_pfn: None,
        }),
    ).unwrap();
    let pfn = pmm.alloc_gfp(Order(0), GFP_MOVABLE).expect("fallback block exists");
    assert_eq!(pmm.pageblock_migratetype(pfn), MigrateType::Movable);
    // SAFETY: pfn is this test's live allocation.
    unsafe { pmm.free(pfn, Order(0)); }

    // The first 2 MiB pageblock is movable after the claim and the second is
    // unmovable. Draining the cached page cannot merge that class boundary.
    assert_eq!(pmm.alloc(Order(10)), Err(Error::NoMem));
    // SAFETY: the failed high-order request completed its drain transition.
    unsafe { pmm.audit(); }
}

#[test]
fn an_unmovable_request_cannot_rise_into_the_movable_zone() {
    let pmm = normal_and_movable();
    let pfn = pmm.alloc_gfp(Order(0), 0).expect("normal zone has free pages");
    assert!(pfn.0 < 2048, "unmovable allocation rose into movable zone: {}", pfn.0);
    assert_eq!(pmm.zone_snapshot()[ZoneType::Movable.index()].free_pages, 2048);
    // SAFETY: pfn is the allocation returned above.
    unsafe { pmm.free(pfn, Order(0)); }
}
