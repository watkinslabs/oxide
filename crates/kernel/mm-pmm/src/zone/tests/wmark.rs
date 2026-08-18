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
    r[ZoneType::Dma.index()][ZoneType::Normal.index()] = 95;
    // A DMA-bounded class owes nothing and clears a mark of 10 with 100 free;
    // a normal class owes 95 on top of it and does not.
    assert!(ok(ZoneType::Dma, 0, 10, AllocWmark::Low, &r, ZoneType::Dma.index(), &a));
    assert!(!ok(ZoneType::Dma, 0, 10, AllocWmark::Low, &r, ZoneType::Normal.index(), &a));
    // The sum is a strict floor: free equal to mark plus reserve is refused,
    // one page more is admitted.
    r[ZoneType::Dma.index()][ZoneType::Normal.index()] = 90;
    assert!(!ok(ZoneType::Dma, 0, 10, AllocWmark::Low, &r, ZoneType::Normal.index(), &a));
    r[ZoneType::Dma.index()][ZoneType::Normal.index()] = 89;
    assert!(ok(ZoneType::Dma, 0, 10, AllocWmark::Low, &r, ZoneType::Normal.index(), &a));
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

// Provenance: the reserve discount is earned by the high-priority flag, and
// the non-blocking discount nests inside it. Mapping "cannot block" straight
// onto both is permissive — an allocation that never asked for the reserve
// would drain what a blockable context is relying on.
#[test]
fn a_caller_that_did_not_ask_for_the_reserve_is_held_to_the_whole_minimum() {
    use crate::zone::{grants_min_reserve, slowpath_wmark, GFP_ATOMIC, GFP_HIGH};
    assert_eq!(slowpath_wmark(false, true), AllocWmark::Min);
    assert_eq!(slowpath_wmark(false, false), AllocWmark::Min);
    assert_eq!(slowpath_wmark(true, true), AllocWmark::MinReserve);
    assert_eq!(slowpath_wmark(true, false), AllocWmark::MinNonBlock);
    // The plain kernel allocation asks for nothing and earns nothing.
    assert!(!grants_min_reserve(0));
    assert!(grants_min_reserve(GFP_HIGH));
    assert!(grants_min_reserve(GFP_ATOMIC));
}

#[test]
fn each_rung_of_the_reserve_is_strictly_deeper_than_the_last() {
    const MARK: u64 = 400;
    const RESERVE: LowmemReserve = [[0; NR_ZONES]; NR_ZONES];
    // The smallest free count each rung accepts is one above its floor.
    fn floor(w: AllocWmark) -> u64 {
        const MARK: u64 = 400;
        const RESERVE: LowmemReserve = [[0; NR_ZONES]; NR_ZONES];
        let mut area = [0u64; crate::ORDERS];
        let mut n = 0u64;
        loop {
            area[0] = n;
            if zone_watermark_ok(ZoneType::Normal, 0, MARK, w, &RESERVE, ZoneType::Normal.index(), &area) { return n; }
            n += 1;
            assert!(n <= MARK + 1, "no free count cleared {w:?}");
        }
    }
    let plain = floor(AllocWmark::Min);
    let reserve = floor(AllocWmark::MinReserve);
    let non_block = floor(AllocWmark::MinNonBlock);
    assert_eq!(plain, MARK + 1);
    assert_eq!(reserve, MARK - MARK / 2 + 1);
    assert_eq!(non_block, { let m = MARK - MARK / 2; m - m / 4 + 1 });
    assert!(non_block < reserve && reserve < plain);
}
