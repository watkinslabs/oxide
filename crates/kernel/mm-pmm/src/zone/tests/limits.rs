// Provenance: zone boundary derivation verified against the two arch
// implementations — the x86_64 ISA/32-bit pair, and the aarch64 firmware
// constraint clamped to the 32-bit line and to the end of RAM.

use crate::zone::limits::{DMA32_LIMIT_BYTES, X86_DMA_LIMIT_BYTES};
use crate::zone::*;

const PAGE: u64 = 4096;
const PFN_16M: u64 = X86_DMA_LIMIT_BYTES / PAGE;
const PFN_4G: u64 = DMA32_LIMIT_BYTES / PAGE;

#[test]
fn x86_64_splits_at_the_isa_and_32_bit_lines() {
    let l = ZoneLimits::x86_64(PFN_4G * 2, PAGE);
    assert_eq!(l.dma_end_pfn, PFN_16M);
    assert_eq!(l.dma32_end_pfn, PFN_4G);
    let layout = ZoneLayout::new(l, PFN_4G * 2);
    assert_eq!(layout.span(ZoneType::Dma), ZoneSpan { start_pfn: 0, end_pfn: PFN_16M });
    assert_eq!(layout.span(ZoneType::Dma32), ZoneSpan { start_pfn: PFN_16M, end_pfn: PFN_4G });
    assert_eq!(layout.span(ZoneType::Normal), ZoneSpan { start_pfn: PFN_4G, end_pfn: PFN_4G * 2 });
    assert!(layout.span(ZoneType::Movable).is_empty());
}

#[test]
fn a_machine_smaller_than_a_boundary_leaves_the_upper_zones_empty() {
    // 1 GiB of RAM: everything above the ISA line is DMA32, nothing is normal.
    let pfn_max = (1u64 << 30) / PAGE;
    let layout = ZoneLayout::new(ZoneLimits::x86_64(pfn_max, PAGE), pfn_max);
    assert_eq!(layout.span(ZoneType::Dma).end_pfn, PFN_16M);
    assert_eq!(layout.span(ZoneType::Dma32), ZoneSpan { start_pfn: PFN_16M, end_pfn: pfn_max });
    assert!(layout.span(ZoneType::Normal).is_empty());
}

#[test]
fn a_machine_smaller_than_the_isa_line_is_all_dma() {
    let pfn_max = 256;
    let layout = ZoneLayout::new(ZoneLimits::x86_64(pfn_max, PAGE), pfn_max);
    assert_eq!(layout.span(ZoneType::Dma), ZoneSpan { start_pfn: 0, end_pfn: pfn_max });
    for z in [ZoneType::Dma32, ZoneType::Normal, ZoneType::Movable] { assert!(layout.span(z).is_empty()); }
}

#[test]
fn aarch64_without_a_firmware_constraint_keeps_a_low_zone_when_ram_reaches_below_4g() {
    // RAM based at 1 GiB: the bus is unconstrained, but a low DMA zone still
    // exists because devices needing one have somewhere to allocate from.
    let pfn_max = PFN_4G * 2;
    let l = ZoneLimits::aarch64(None, 1u64 << 30, pfn_max, PAGE);
    assert_eq!(l.dma_end_pfn, PFN_4G);
    assert_eq!(l.dma32_end_pfn, PFN_4G);
    let layout = ZoneLayout::new(l, pfn_max);
    // DMA absorbs the whole low range; DMA32 is then empty and NORMAL is the rest.
    assert_eq!(layout.span(ZoneType::Dma).end_pfn, PFN_4G);
    assert!(layout.span(ZoneType::Dma32).is_empty());
    assert_eq!(layout.span(ZoneType::Normal), ZoneSpan { start_pfn: PFN_4G, end_pfn: pfn_max });
}

#[test]
fn aarch64_honours_a_narrower_firmware_constraint() {
    // A 30-bit bus master limit: the DMA zone ends at 1 GiB, not 4 GiB.
    let pfn_max = PFN_4G * 2;
    let l = ZoneLimits::aarch64(Some((1u64 << 30) - 1), 0, pfn_max, PAGE);
    assert_eq!(l.dma_end_pfn, (1u64 << 30) / PAGE);
    let layout = ZoneLayout::new(l, pfn_max);
    assert_eq!(layout.span(ZoneType::Dma32), ZoneSpan { start_pfn: (1u64 << 30) / PAGE, end_pfn: PFN_4G });
}

#[test]
fn aarch64_clamps_every_boundary_to_the_end_of_ram() {
    let pfn_max = 512;
    let l = ZoneLimits::aarch64(Some((1u64 << 30) - 1), 0, pfn_max, PAGE);
    assert_eq!(l.dma_end_pfn, pfn_max);
    assert_eq!(l.dma32_end_pfn, pfn_max);
}

#[test]
fn spans_partition_the_pfn_range_without_gap_or_overlap() {
    let pfn_max = PFN_4G + 12345;
    let layout = ZoneLayout::new(ZoneLimits::x86_64(pfn_max, PAGE), pfn_max);
    let mut cur = 0;
    for zi in 0..NR_ZONES {
        let s = layout.span_at(zi);
        assert_eq!(s.start_pfn, cur, "zone {zi} starts where the previous ended");
        assert!(s.end_pfn >= s.start_pfn);
        cur = s.end_pfn;
    }
    assert_eq!(cur, pfn_max);
    assert_eq!(layout.pfn_max(), pfn_max);
}

#[test]
fn every_pfn_below_the_top_resolves_to_exactly_one_zone() {
    let pfn_max = PFN_16M + 64;
    let layout = ZoneLayout::new(ZoneLimits::x86_64(pfn_max, PAGE), pfn_max);
    for pfn in [0, 1, PFN_16M - 1, PFN_16M, pfn_max - 1] {
        let hits = (0..NR_ZONES).filter(|zi| layout.span_at(*zi).contains(pfn)).count();
        assert_eq!(hits, 1, "pfn {pfn} belongs to exactly one zone");
    }
    assert_eq!(layout.zone_of(PFN_16M - 1), Some(ZoneType::Dma));
    assert_eq!(layout.zone_of(PFN_16M), Some(ZoneType::Dma32));
    assert_eq!(layout.zone_of(pfn_max), None);
    assert_eq!(layout.index_of(pfn_max), NR_ZONES);
}

#[test]
fn a_single_normal_layout_puts_everything_in_normal() {
    let layout = ZoneLayout::single_normal(1024);
    assert_eq!(layout.span(ZoneType::Normal), ZoneSpan { start_pfn: 0, end_pfn: 1024 });
    assert!(layout.span(ZoneType::Dma).is_empty());
}
