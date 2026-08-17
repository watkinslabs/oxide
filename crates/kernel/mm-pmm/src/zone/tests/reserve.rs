// Provenance: the reserve matrix verified against the reference's per-zone
// lowmem reserve — the sum of managed pages in every strictly higher zone,
// divided by the zone's ratio, monotonically non-decreasing in the second
// index, and zero for an unpopulated zone or a zero ratio.

use crate::zone::*;

const RATIO: [u64; NR_ZONES] = DEFAULT_LOWMEM_RESERVE_RATIO;

#[test]
fn a_zone_reserves_a_fraction_of_what_the_higher_zones_hold() {
    let managed = [4096u64, 1_000_000, 2_000_000, 0];
    let r = lowmem_reserve(managed, RATIO);
    assert_eq!(r[ZoneType::Dma.index()][ZoneType::Dma32.index()], 1_000_000 / 256);
    assert_eq!(r[ZoneType::Dma.index()][ZoneType::Normal.index()], 3_000_000 / 256);
    assert_eq!(r[ZoneType::Dma32.index()][ZoneType::Normal.index()], 2_000_000 / 256);
    assert_eq!(r[ZoneType::Normal.index()][ZoneType::Movable.index()], 0 / 32);
}

#[test]
fn a_zone_owes_nothing_to_a_class_that_cannot_go_higher_than_itself() {
    let r = lowmem_reserve([4096, 1_000_000, 2_000_000, 0], RATIO);
    for i in 0..NR_ZONES { for j in 0..=i { assert_eq!(r[i][j], 0, "zone {i} owes nothing at bound {j}"); } }
}

#[test]
fn the_reserve_never_shrinks_as_the_class_gains_zones() {
    let r = lowmem_reserve([4096, 1_000_000, 2_000_000, 500_000], RATIO);
    for i in 0..NR_ZONES {
        for j in 1..NR_ZONES { assert!(r[i][j] >= r[i][j - 1], "zone {i}: reserve fell from bound {} to {j}", j - 1); }
    }
}

#[test]
fn an_unpopulated_zone_and_a_zero_ratio_both_reserve_nothing() {
    let r = lowmem_reserve([0, 1_000_000, 2_000_000, 0], RATIO);
    assert_eq!(r[ZoneType::Dma.index()], [0; NR_ZONES]);
    let r = lowmem_reserve([4096, 1_000_000, 2_000_000, 0], [0, 256, 32, 0]);
    assert_eq!(r[ZoneType::Dma.index()], [0; NR_ZONES]);
}

#[test]
fn a_single_zone_machine_carries_no_reserve_at_all() {
    let r = lowmem_reserve([256, 0, 0, 0], RATIO);
    assert_eq!(r, [[0; NR_ZONES]; NR_ZONES]);
}
