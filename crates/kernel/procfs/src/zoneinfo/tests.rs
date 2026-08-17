// Layout provenance for `/proc/zoneinfo` and `/proc/buddyinfo`. Both files
// are parsed positionally by userspace, so the tests pin the field names, the
// order, the reserve tuple's arity, and which zones appear at all.

use alloc::string::String;
use alloc::vec::Vec;

use super::{render, render_buddyinfo, NODE};
use pmm::watermark::ZoneWatermarks;
use pmm::zone::{ZoneType, NR_ZONES};
use pmm::ZoneStat;

fn row(zone: ZoneType, present: u64, managed: u64) -> ZoneStat {
    let mut free_orders = [0u64; pmm::ORDERS];
    free_orders[0] = 7;
    free_orders[3] = 2;
    ZoneStat {
        zone,
        start_pfn: 16,
        spanned_pages: present + 8,
        present_pages: present,
        managed_pages: managed,
        free_pages: 100,
        free_orders,
        wmark: ZoneWatermarks { min: 33, low: 41, high: 49, promo: 57 },
        lowmem_reserve: [0, 1, 2, 3],
    }
}

fn zones() -> [ZoneStat; NR_ZONES] {
    let mut z = [ZoneStat::EMPTY; NR_ZONES];
    z[ZoneType::Dma.index()] = row(ZoneType::Dma, 3998, 3968);
    z[ZoneType::Dma32.index()] = row(ZoneType::Dma32, 1_000_000, 999_000);
    z[ZoneType::Normal.index()] = row(ZoneType::Normal, 2_000_000, 2_000_000);
    // Movable stays as it is on every platform that requests no movable core:
    // present zero, and therefore printed only down to the reserve row.
    z[ZoneType::Movable.index()].zone = ZoneType::Movable;
    z
}

fn body() -> String { String::from_utf8(render(NODE, &zones())).unwrap() }

#[test]
fn a_populated_zone_carries_every_field_in_order() {
    let b = body();
    let dma = b.split("Node 0, zone").nth(1).unwrap();
    let names: Vec<&str> = dma.lines().skip(1).map(|l| l.split_whitespace().next().unwrap_or("")).collect();
    assert_eq!(&names[..11], &["pages", "boost", "min", "low", "high", "promo", "spanned", "present", "managed", "cma", "protection:"]);
    assert!(dma.contains("\n        present  3998"), "{dma}");
    assert!(dma.contains("\n        managed  3968"), "{dma}");
    assert!(dma.contains("\n        promo    57"), "{dma}");
    assert!(dma.contains("\n  start_pfn:           16"), "{dma}");
}

#[test]
fn the_zone_name_is_right_aligned_the_way_a_reader_expects() {
    let b = body();
    assert!(b.starts_with("Node 0, zone      DMA\n"), "{b}");
    assert!(b.contains("Node 0, zone    DMA32\n"), "{b}");
    assert!(b.contains("Node 0, zone   Normal\n"), "{b}");
}

#[test]
fn the_reserve_tuple_has_one_entry_per_zone() {
    let b = body();
    let tuple = b.split("protection: (").nth(1).unwrap().split(')').next().unwrap();
    assert_eq!(tuple.split(',').count(), NR_ZONES);
}

#[test]
fn an_unpopulated_zone_stops_after_its_reserve_row() {
    let b = body();
    let movable = b.split("Node 0, zone  Movable").nth(1).expect("the empty zone still appears");
    assert!(movable.contains("protection: ("), "{movable}");
    assert!(!movable.contains("start_pfn"), "nothing below the reserve describes an empty zone: {movable}");
}

#[test]
fn every_zone_slot_appears_because_the_reserve_matrix_spans_them_all() {
    let b = body();
    assert_eq!(b.matches("Node 0, zone").count(), NR_ZONES);
}

#[test]
fn buddyinfo_carries_one_row_per_populated_zone_with_every_order() {
    let b = String::from_utf8(render_buddyinfo(NODE, &zones())).unwrap();
    let rows: Vec<&str> = b.lines().collect();
    assert_eq!(rows.len(), 3, "the empty movable zone is not a row: {b}");
    assert!(rows[0].starts_with("Node 0, zone      DMA "), "{b}");
    let counts: Vec<&str> = rows[0].split("DMA ").nth(1).unwrap().split_whitespace().collect();
    assert_eq!(counts.len(), pmm::ORDERS);
    assert_eq!(counts[0], "7");
    assert_eq!(counts[3], "2");
}
