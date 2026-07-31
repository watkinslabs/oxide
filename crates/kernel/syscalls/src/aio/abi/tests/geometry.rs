// Ring sizing: what `nr_events` a caller really gets, and when the request is
// refused. The rounded-up slot count is published in `aio_ring.nr`, so it is a
// user-visible number, not an implementation detail.

use crate::aio_abi::geometry::*;
use syscall::errno::Errno;

const PAGE: u64 = 4096;
const MAXNR: u64 = AIO_MAX_NR_DEFAULT;

/// One CPU keeps the per-CPU floor out of the way for the arithmetic tests.
fn plan1(req: u32) -> Result<RingPlan, Errno> { plan_ring(req, 1, PAGE, MAXNR) }

#[test]
fn slot_count_is_doubled_padded_and_page_rounded() {
    // 128 asked for → 256 doubled → 258 padded → 32 + 258*32 = 8288 bytes
    // → 3 pages → (3*4096 - 32)/32 = 383 slots.
    let p = plan1(128).unwrap();
    assert_eq!(p.max_reqs, 128);
    assert_eq!(p.nr_pages, 3);
    assert_eq!(p.nr_events, 383);
    // The published count always exceeds what the caller asked for.
    assert!(p.nr_events > p.max_reqs);
}

#[test]
fn a_single_event_request_still_gets_a_whole_page() {
    let p = plan1(1).unwrap();
    assert_eq!(p.nr_pages, 1);
    assert_eq!(p.nr_events, 127); // (4096 - 32) / 32
    assert_eq!(p.max_reqs, 1);
}

#[test]
fn per_cpu_floor_raises_a_small_request() {
    // 16 CPUs → floor 64 → max(2, 64) = 64 → 128 doubled → 130 padded
    // → 32 + 4160 = 4192 bytes → 2 pages.
    let p = plan_ring(2, 16, PAGE, MAXNR).unwrap();
    assert_eq!(p.nr_pages, 2);
    assert_eq!(p.nr_events, 255);
    // The charge against the system limit is still what the caller asked for.
    assert_eq!(p.max_reqs, 2);
}

#[test]
fn larger_pages_yield_more_slots_for_the_same_request() {
    let p4 = plan_ring(64, 1, 4096, MAXNR).unwrap();
    let p16 = plan_ring(64, 1, 16384, MAXNR).unwrap();
    assert_eq!(p4.nr_pages, 2);
    assert_eq!(p4.nr_events, 255);
    assert_eq!(p16.nr_pages, 1);
    assert_eq!(p16.nr_events, 511);
}

#[test]
fn oversized_request_is_einval_not_eagain() {
    // The 256 MiB cap is tested on the DOUBLED count, so the boundary sits at
    // half of 0x800000 — exactly 0x400000 still fits, one more does not.
    assert_eq!(plan_ring(0x40_0001, 1, PAGE, u64::MAX), Err(Errno::Einval));
    assert!(plan_ring(0x40_0000, 1, PAGE, u64::MAX).is_ok());
}

#[test]
fn cap_is_checked_before_the_system_limit() {
    // Both would fail; EINVAL (the cap) must win over EAGAIN (the limit).
    assert_eq!(plan_ring(0x40_0001, 1, PAGE, 8), Err(Errno::Einval));
    // Just inside the cap, the system limit is what rejects it.
    assert_eq!(plan_ring(0x40_0000, 1, PAGE, 8), Err(Errno::Eagain));
}

#[test]
fn request_above_the_system_limit_is_eagain() {
    assert_eq!(plan_ring(9, 1, PAGE, 8), Err(Errno::Eagain));
    assert!(plan_ring(8, 1, PAGE, 8).is_ok());
}

#[test]
fn doubling_that_wraps_to_zero_is_eagain_not_a_zero_ring() {
    // 0x8000_0000 doubles to 0 in 32 bits; the cap check sees a small value,
    // so the zero test is what must catch it.
    assert_eq!(plan_ring(0x8000_0000, 1, PAGE, u64::MAX), Err(Errno::Eagain));
}

#[test]
fn aio_nr_admission_accumulates_and_refuses() {
    assert_eq!(admit_aio_nr(0, 100, 1000), Ok(100));
    assert_eq!(admit_aio_nr(900, 100, 1000), Ok(1000));
    assert_eq!(admit_aio_nr(901, 100, 1000), Err(Errno::Eagain));
    assert_eq!(admit_aio_nr(u64::MAX, 1, u64::MAX), Err(Errno::Eagain));
}

#[test]
fn default_system_limit_is_the_documented_one() {
    assert_eq!(AIO_MAX_NR_DEFAULT, 65536);
}

#[test]
fn buddy_order_covers_the_page_count() {
    assert_eq!(order_for_pages(1), 0);
    assert_eq!(order_for_pages(2), 1);
    assert_eq!(order_for_pages(3), 2);
    assert_eq!(order_for_pages(4), 2);
    assert_eq!(order_for_pages(5), 3);
    assert_eq!(order_for_pages(64), 6);
    for pages in 1u64..300 { assert!((1u64 << order_for_pages(pages)) >= pages); }
}
