// Provenance: a bus-master address bound resolves to the zone whose top it
// falls at or below, and a block that still lands outside the bound narrows
// the selection one zone at a time until the narrowest zone has been tried.
// Verified against the reference's DMA-direct mapping layer, which is where
// the address-to-zone-bits conversion and the retry ladder live there too.

use crate::zone::*;

/// Layout with both addressable zones populated: DMA `[0,64)`, DMA32
/// `[64,256)`, NORMAL `[256,1024)`.
fn split() -> ZoneLayout {
    ZoneLayout::new(ZoneLimits { dma_end_pfn: 64, dma32_end_pfn: 256, movable_start_pfn: None }, 1024)
}

#[test]
fn a_bound_at_or_below_the_dma_top_selects_the_dma_zone() {
    let l = split();
    assert_eq!(gfp_for_pfn_limit(&l, 1), GFP_DMA);
    assert_eq!(gfp_for_pfn_limit(&l, 63), GFP_DMA);
    assert_eq!(gfp_for_pfn_limit(&l, 64), GFP_DMA);
}

#[test]
fn a_bound_inside_the_thirty_two_bit_range_selects_dma32() {
    let l = split();
    assert_eq!(gfp_for_pfn_limit(&l, 65), GFP_DMA32);
    assert_eq!(gfp_for_pfn_limit(&l, 256), GFP_DMA32);
}

#[test]
fn a_bound_above_every_addressable_zone_names_no_zone() {
    let l = split();
    assert_eq!(gfp_for_pfn_limit(&l, 257), 0);
    assert_eq!(gfp_for_pfn_limit(&l, u64::MAX), 0);
}

#[test]
fn an_empty_low_zone_is_never_selected_by_a_bound_above_it() {
    // No DMA zone: its span is empty, so no bound can fall at or below its
    // top and the narrower selection is unreachable from the resolver.
    let l = ZoneLayout::new(ZoneLimits { dma_end_pfn: 0, dma32_end_pfn: 256, movable_start_pfn: None }, 1024);
    assert_eq!(gfp_for_pfn_limit(&l, 1), GFP_DMA32);
    assert_eq!(gfp_for_pfn_limit(&l, 256), GFP_DMA32);
}

#[test]
fn the_narrowing_ladder_descends_one_zone_at_a_time_and_terminates() {
    assert_eq!(narrow_zone_bits(0), Some(GFP_DMA32));
    assert_eq!(narrow_zone_bits(GFP_DMA32), Some(GFP_DMA));
    assert_eq!(narrow_zone_bits(GFP_DMA), None);
}

#[test]
fn narrowing_replaces_the_zone_bits_and_keeps_everything_else() {
    let ctx = GFP_HIGH | GFP_KSWAPD_RECLAIM;
    assert_eq!(narrow_zone_bits(ctx), Some(ctx | GFP_DMA32));
    assert_eq!(narrow_zone_bits(ctx | GFP_DMA32), Some(ctx | GFP_DMA));
    // The replaced bit is gone, not merely joined by a narrower one: DMA32
    // and DMA together name no zone at all.
    assert_eq!(narrow_zone_bits(GFP_DMA32).map(gfp_zone), Some(Ok(ZoneType::Dma)));
}
