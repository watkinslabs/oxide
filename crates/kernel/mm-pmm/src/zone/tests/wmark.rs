// Provenance: the allocation gate verified against the reference watermark
// check — free base pages must strictly exceed the mark plus the reserve owed
// to the requesting class, the pages locked inside oversized blocks do not
// count, a high-order request additionally needs a block of that order, and
// the reserve-bearing contexts get a documented fraction of the mark back.

use crate::zone::*;
use crate::ORDERS;

fn area(counts: &[(usize, u64)]) -> ZoneFreeArea {
    let mut a = [0u64; ORDERS];
    for (o, n) in counts { a[*o] = *n; }
    a
}

const NO_RESERVE: LowmemReserve = [[0; NR_ZONES]; NR_ZONES];

fn ok(zone: ZoneType, order: u8, mark: u64, w: AllocWmark, r: &LowmemReserve, hi: usize, a: &ZoneFreeArea) -> bool {
    zone_watermark_ok(zone, order, mark, w, r, hi, a)
}

#[test]
fn free_pages_must_strictly_exceed_the_mark() {
    let a = area(&[(0, 100)]);
    assert!(ok(ZoneType::Dma, 0, 99, AllocWmark::Low, &NO_RESERVE, 2, &a));
    assert!(!ok(ZoneType::Dma, 0, 100, AllocWmark::Low, &NO_RESERVE, 2, &a));
    assert!(!ok(ZoneType::Dma, 0, 101, AllocWmark::Low, &NO_RESERVE, 2, &a));
}

#[test]
fn the_reserve_owed_to_the_requesting_class_is_added_to_the_mark() {
    let a = area(&[(0, 100)]);
    let mut r = NO_RESERVE;
    r[ZoneType::Dma.index()][ZoneType::Normal.index()] = 80;
    // A DMA-bounded class owes nothing and passes; a normal class does not.
    assert!(ok(ZoneType::Dma, 0, 10, AllocWmark::Low, &r, ZoneType::Dma.index(), &a));
    assert!(!ok(ZoneType::Dma, 0, 10, AllocWmark::Low, &r, ZoneType::Normal.index(), &a));
}

#[test]
fn pages_locked_inside_oversized_blocks_do_not_count_toward_the_mark() {
    // Two order-4 blocks: 32 base pages free, but an order-4 request can only
    // ever be handed 16 of them, so 15 are unusable for the check.
    let a = area(&[(4, 2)]);
    assert!(ok(ZoneType::Normal, 4, 16, AllocWmark::Low, &NO_RESERVE, 2, &a));
    assert!(!ok(ZoneType::Normal, 4, 17, AllocWmark::Low, &NO_RESERVE, 2, &a));
}

#[test]
fn a_high_order_request_needs_a_block_of_that_order_not_merely_free_pages() {
    // 64 order-0 pages clear any small mark, but no order-3 block exists.
    let a = area(&[(0, 64)]);
    assert!(ok(ZoneType::Normal, 0, 0, AllocWmark::Low, &NO_RESERVE, 2, &a));
    assert!(!ok(ZoneType::Normal, 3, 0, AllocWmark::Low, &NO_RESERVE, 2, &a));
    // One order-5 block satisfies an order-3 request.
    let a = area(&[(0, 64), (5, 1)]);
    assert!(ok(ZoneType::Normal, 3, 0, AllocWmark::Low, &NO_RESERVE, 2, &a));
}

#[test]
fn reserve_bearing_contexts_reach_further_into_the_mark() {
    let a = area(&[(0, 60)]);
    // 60 free against a mark of 100: refused outright, half the mark still
    // refuses, and the non-blocking share (100 -> 50 -> 38) admits it.
    assert!(!ok(ZoneType::Normal, 0, 100, AllocWmark::Min, &NO_RESERVE, 2, &a));
    assert!(ok(ZoneType::Normal, 0, 100, AllocWmark::MinReserve, &NO_RESERVE, 2, &a));
    let a = area(&[(0, 45)]);
    assert!(!ok(ZoneType::Normal, 0, 100, AllocWmark::MinReserve, &NO_RESERVE, 2, &a));
    assert!(ok(ZoneType::Normal, 0, 100, AllocWmark::MinNonBlock, &NO_RESERVE, 2, &a));
}

#[test]
fn an_empty_zone_never_passes() {
    let a = area(&[]);
    for w in [AllocWmark::Low, AllocWmark::Min, AllocWmark::MinReserve, AllocWmark::MinNonBlock] {
        assert!(!ok(ZoneType::Dma, 0, 0, w, &NO_RESERVE, 2, &a));
    }
}

#[test]
fn free_pages_sums_the_area_by_order() {
    assert_eq!(crate::zone::wmark::free_pages(&area(&[(0, 3), (2, 5)])), 3 + 5 * 4);
}
