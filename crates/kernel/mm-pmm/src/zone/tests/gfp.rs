// Provenance: the flag→zone map verified against the reference page
// allocator's zone table, including every combination it rejects outright.

use crate::zone::*;

#[test]
fn no_zone_bits_selects_normal() {
    assert_eq!(gfp_zone(0), Ok(ZoneType::Normal));
}

#[test]
fn unrelated_flags_outside_the_zone_mask_do_not_change_the_zone() {
    // Reclaim/context bits live above the zone mask and must be ignored here.
    assert_eq!(gfp_zone(0xffff_fff0), Ok(ZoneType::Normal));
    assert_eq!(gfp_zone(0xffff_fff0 | GFP_DMA32), Ok(ZoneType::Dma32));
}

#[test]
fn each_single_zone_bit_selects_its_zone() {
    assert_eq!(gfp_zone(GFP_DMA), Ok(ZoneType::Dma));
    assert_eq!(gfp_zone(GFP_DMA32), Ok(ZoneType::Dma32));
    // No separate high-memory zone exists on a 64-bit direct map.
    assert_eq!(gfp_zone(GFP_HIGHMEM), Ok(ZoneType::Normal));
    assert_eq!(gfp_zone(GFP_MOVABLE), Ok(ZoneType::Normal));
}

#[test]
fn movable_composes_with_exactly_one_other_selector() {
    assert_eq!(gfp_zone(GFP_MOVABLE | GFP_DMA), Ok(ZoneType::Dma));
    assert_eq!(gfp_zone(GFP_MOVABLE | GFP_DMA32), Ok(ZoneType::Dma32));
    assert_eq!(gfp_zone(GFP_MOVABLE | GFP_HIGHMEM), Ok(ZoneType::Movable));
}

#[test]
fn contradictory_selectors_are_rejected_rather_than_resolved() {
    for bad in [
        GFP_DMA | GFP_HIGHMEM,
        GFP_DMA | GFP_DMA32,
        GFP_DMA32 | GFP_HIGHMEM,
        GFP_DMA | GFP_DMA32 | GFP_HIGHMEM,
        GFP_MOVABLE | GFP_HIGHMEM | GFP_DMA,
        GFP_MOVABLE | GFP_DMA32 | GFP_DMA,
        GFP_MOVABLE | GFP_DMA32 | GFP_HIGHMEM,
        GFP_MOVABLE | GFP_DMA32 | GFP_DMA | GFP_HIGHMEM,
    ] {
        assert_eq!(gfp_zone(bad), Err(GfpError), "flags {bad:#x} name no single zone");
    }
}

#[test]
fn every_zone_mask_value_is_either_a_zone_or_an_error() {
    // Exhaustive over the mask: no combination may be left undecided.
    let mut ok = 0;
    for bits in 0..=GFP_ZONEMASK {
        if gfp_zone(bits).is_ok() { ok += 1; }
    }
    assert_eq!(ok, 8, "eight of the sixteen combinations name a zone");
}
