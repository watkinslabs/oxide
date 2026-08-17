// Provenance: fallback order verified against the reference zonelist build,
// which records populated zones from the highest index downward, and against
// its walk, which enters at the first entry at or below the permitted index.

use crate::zone::*;
use std::vec::Vec;

fn walk(list: &Zonelist, hi: ZoneType) -> Vec<ZoneType> { list.walk(hi.index()).collect() }

fn all_populated() -> Zonelist { Zonelist::build([true; NR_ZONES]) }

#[test]
fn the_list_runs_from_the_highest_zone_downward() {
    let l = all_populated();
    assert_eq!(l.len(), NR_ZONES);
    assert_eq!(walk(&l, ZoneType::Movable), [ZoneType::Movable, ZoneType::Normal, ZoneType::Dma32, ZoneType::Dma]);
}

#[test]
fn unpopulated_zones_never_appear() {
    let l = Zonelist::build([true, false, true, false]);
    assert_eq!(l.len(), 2);
    assert_eq!(walk(&l, ZoneType::Movable), [ZoneType::Normal, ZoneType::Dma]);
    assert!(Zonelist::default().is_empty());
}

#[test]
fn a_bounded_request_enters_below_its_bound_and_only_descends() {
    let l = all_populated();
    assert_eq!(walk(&l, ZoneType::Normal), [ZoneType::Normal, ZoneType::Dma32, ZoneType::Dma]);
    assert_eq!(walk(&l, ZoneType::Dma32), [ZoneType::Dma32, ZoneType::Dma]);
    assert_eq!(walk(&l, ZoneType::Dma), [ZoneType::Dma]);
}

#[test]
fn no_walk_ever_yields_a_zone_above_its_bound() {
    // The whole point of the row: exhaustive over bounds and over every
    // populated-set, no reachable zone may exceed the permitted index.
    let l = all_populated();
    for mask in 0..(1u32 << NR_ZONES) {
        let mut populated = [false; NR_ZONES];
        for zi in 0..NR_ZONES { populated[zi] = mask & (1 << zi) != 0; }
        let list = Zonelist::build(populated);
        for hi in 0..NR_ZONES {
            for z in list.walk(hi) {
                assert!(z.index() <= hi, "walk for bound {hi} reached {z:?}");
                assert!(populated[z.index()], "walk reached an unpopulated zone");
            }
        }
    }
    let _ = l;
}

#[test]
fn a_bound_below_every_populated_zone_yields_nothing() {
    let l = Zonelist::build([false, false, true, true]);
    assert_eq!(walk(&l, ZoneType::Dma32), []);
    assert_eq!(walk(&l, ZoneType::Dma), []);
}
