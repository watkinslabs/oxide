use super::hstate::HstateCounts;
use super::sizes::{size_from_flags, size_from_log, size_log_from_flags, HugePageSize,
                   DEFAULT_HUGE_SHIFT, GIGANTIC_HUGE_SHIFT, HUGE_FLAG_ENCODE_SHIFT};
use super::subpool::{Subpool, NO_LIMIT};

fn counts(max: u64, nr: u64, free: u64, resv: u64, surplus: u64, overcommit: u64) -> HstateCounts {
    HstateCounts { max, nr, free, resv, surplus, overcommit }
}

// ---- sizes ---------------------------------------------------------------

#[test]
fn a_zero_size_log_selects_the_default_granule() {
    assert_eq!(size_from_log(0), Some(HugePageSize::Huge2M));
}

#[test]
fn each_supported_granule_round_trips_through_its_size_log() {
    for s in [HugePageSize::Huge2M, HugePageSize::Huge1G] {
        assert_eq!(size_from_log(s.shift()), Some(s));
        assert_eq!(s.bytes(), 1u64 << s.shift());
    }
    assert_eq!(HugePageSize::Huge2M.shift(), DEFAULT_HUGE_SHIFT);
    assert_eq!(HugePageSize::Huge1G.shift(), GIGANTIC_HUGE_SHIFT);
}

#[test]
fn an_unsupported_size_log_is_refused_rather_than_rounded() {
    for log in [12u32, 16, 20, 22, 34, 63] {
        assert_eq!(size_from_log(log), None, "size log {log} must not resolve");
    }
}

#[test]
fn the_size_log_field_is_read_out_of_the_flag_word() {
    let flags = (DEFAULT_HUGE_SHIFT as u64) << HUGE_FLAG_ENCODE_SHIFT;
    assert_eq!(size_log_from_flags(flags), DEFAULT_HUGE_SHIFT);
    assert_eq!(size_from_flags(flags), Some(HugePageSize::Huge2M));
    let gig = (GIGANTIC_HUGE_SHIFT as u64) << HUGE_FLAG_ENCODE_SHIFT;
    assert_eq!(size_from_flags(gig), Some(HugePageSize::Huge1G));
}

#[test]
fn low_flag_bits_never_leak_into_the_size_log_field() {
    // Every ordinary mmap/memfd flag lives below the encode shift.
    assert_eq!(size_log_from_flags(0xffff_ffff & ((1 << HUGE_FLAG_ENCODE_SHIFT) - 1)), 0);
}

#[test]
fn a_leaf_resolves_back_to_the_granule_that_installed_it() {
    for g in [HugePageSize::Huge2M, HugePageSize::Huge1G] {
        assert_eq!(HugePageSize::from_leaf(g.leaf()), Some(g));
    }
    // A base leaf names no huge granule, so a teardown walk can never mistake
    // an ordinary page for a pool page and hand it to the pool.
    assert_eq!(HugePageSize::from_leaf(hal::PageSize::P4K), None);
}

#[test]
fn a_granule_maps_to_the_page_table_leaf_that_covers_it() {
    assert_eq!(HugePageSize::Huge2M.leaf().bytes(), HugePageSize::Huge2M.bytes());
    assert_eq!(HugePageSize::Huge1G.leaf().bytes(), HugePageSize::Huge1G.bytes());
    assert_eq!(HugePageSize::Huge2M.nr_base_pages(), 512);
    assert_eq!(HugePageSize::Huge2M.order().0, 9);
    assert_eq!(HugePageSize::Huge1G.order().0, 18);
}

// ---- hstate resize -------------------------------------------------------

#[test]
fn growing_an_empty_pool_allocates_the_whole_target() {
    let c = counts(0, 0, 0, 0, 0, 0);
    let p = c.plan_resize(8);
    assert_eq!((p.absorb_surplus, p.alloc, p.release), (0, 8, 0));
}

#[test]
fn growing_absorbs_surplus_before_allocating_fresh_memory() {
    // 3 pages owned, all surplus. Asking for 5 persistent must reclassify the
    // 3 it already holds and allocate only 2 more.
    let c = counts(0, 3, 3, 0, 3, 8);
    let p = c.plan_resize(5);
    assert_eq!((p.absorb_surplus, p.alloc, p.release), (3, 2, 0));
}

#[test]
fn commit_resize_moves_absorbed_pages_out_of_surplus_without_changing_nr() {
    let mut c = counts(0, 3, 3, 0, 3, 8);
    let p = c.plan_resize(5);
    c.commit_resize(5, p.absorb_surplus, p.alloc, 0);
    assert_eq!(c.surplus, 0);
    assert_eq!(c.nr, 5);
    assert_eq!(c.persistent(), 5);
    assert_eq!(c.free, 5);
}

#[test]
fn shrinking_releases_only_free_pages() {
    let c = counts(10, 10, 4, 0, 0, 0);
    let p = c.plan_resize(0);
    assert_eq!(p.release, 4, "6 pages are handed out and cannot be released");
}

#[test]
fn shrinking_never_releases_a_page_a_reservation_still_covers() {
    // 10 owned, all free, but 6 are promised to mappings that have not
    // faulted. A shrink to zero may take only the 4 unpromised ones.
    let c = counts(10, 10, 10, 6, 0, 0);
    let p = c.plan_resize(0);
    assert_eq!(p.release, 4);
}

#[test]
fn a_resize_to_the_current_size_moves_nothing() {
    let c = counts(6, 6, 6, 0, 0, 0);
    let p = c.plan_resize(6);
    assert_eq!((p.absorb_surplus, p.alloc, p.release), (0, 0, 0));
}

// ---- hstate reservation --------------------------------------------------

#[test]
fn a_reservation_within_the_unpromised_free_pages_needs_no_new_memory() {
    let c = counts(10, 10, 10, 2, 0, 0);
    assert_eq!(c.plan_reserve(8), Ok(0));
}

#[test]
fn a_reservation_past_the_unpromised_free_pages_needs_surplus() {
    let c = counts(10, 10, 10, 2, 0, 4);
    assert_eq!(c.plan_reserve(10), Ok(2));
}

#[test]
fn a_reservation_past_the_overcommit_ceiling_is_refused() {
    let c = counts(10, 10, 10, 2, 0, 1);
    assert_eq!(c.plan_reserve(10), Err(()));
}

#[test]
fn two_reservations_cannot_both_be_promised_the_same_page() {
    let mut c = counts(4, 4, 4, 0, 0, 0);
    assert_eq!(c.plan_reserve(4), Ok(0));
    c.commit_reserve(4, 0);
    assert_eq!(c.plan_reserve(1), Err(()), "every page is already promised");
}

#[test]
fn commit_reserve_records_surplus_pages_as_owned_free_and_surplus() {
    let mut c = counts(0, 0, 0, 0, 0, 8);
    let need = c.plan_reserve(3).unwrap();
    assert_eq!(need, 3);
    c.commit_reserve(3, need);
    assert_eq!((c.nr, c.free, c.surplus, c.resv), (3, 3, 3, 3));
    assert_eq!(c.persistent(), 0);
}

#[test]
fn unreserve_gives_the_promise_back() {
    let mut c = counts(4, 4, 4, 3, 0, 0);
    c.unreserve(3);
    assert_eq!(c.resv, 0);
    assert_eq!(c.plan_reserve(4), Ok(0));
}

// ---- hstate hand-out -----------------------------------------------------

#[test]
fn a_reserved_dequeue_consumes_the_reservation_with_the_page() {
    let mut c = counts(4, 4, 4, 4, 0, 0);
    assert!(c.dequeue(true));
    assert_eq!((c.free, c.resv), (3, 3));
}

#[test]
fn an_unreserved_dequeue_cannot_take_a_promised_page() {
    let mut c = counts(4, 4, 4, 4, 0, 0);
    assert!(!c.dequeue(false), "all four free pages are promised elsewhere");
    assert_eq!((c.free, c.resv), (4, 4));
}

#[test]
fn an_unreserved_dequeue_takes_an_unpromised_page() {
    let mut c = counts(4, 4, 4, 3, 0, 0);
    assert!(c.dequeue(false));
    assert_eq!((c.free, c.resv), (3, 3));
}

#[test]
fn dequeue_on_an_empty_pool_fails_without_moving_a_counter() {
    let mut c = counts(0, 0, 0, 0, 0, 0);
    assert!(!c.dequeue(false));
    assert!(!c.dequeue(true));
    assert_eq!(c, counts(0, 0, 0, 0, 0, 0));
}

#[test]
fn enqueue_and_dequeue_round_trip() {
    let mut c = counts(2, 2, 2, 0, 0, 0);
    assert!(c.dequeue(false));
    c.enqueue();
    assert_eq!(c.free, 2);
}

#[test]
fn surplus_is_returned_only_beyond_every_outstanding_promise() {
    let c = counts(0, 5, 5, 3, 5, 8);
    assert_eq!(c.surplus_to_return(), 2);
    let none = counts(0, 5, 2, 3, 5, 8);
    assert_eq!(none.surplus_to_return(), 0);
}

#[test]
fn commit_return_surplus_drops_the_pages_from_every_counter() {
    let mut c = counts(0, 5, 5, 3, 5, 8);
    let n = c.surplus_to_return();
    c.commit_return_surplus(n);
    assert_eq!((c.nr, c.free, c.surplus), (3, 3, 3));
}

// ---- subpool -------------------------------------------------------------

#[test]
fn an_unlimited_subpool_is_not_needed_at_all() {
    assert!(!Subpool::is_limited(NO_LIMIT, NO_LIMIT));
    assert!(Subpool::is_limited(4, NO_LIMIT));
    assert!(Subpool::is_limited(NO_LIMIT, 4));
}

#[test]
fn a_subpool_refuses_a_charge_past_its_maximum() {
    let mut sp = Subpool::new(2, NO_LIMIT);
    assert!(sp.get_pages(1).is_ok());
    assert!(sp.get_pages(1).is_ok());
    assert_eq!(sp.get_pages(1), Err(()));
    assert_eq!(sp.used_hpages, 2, "a refused charge must not be recorded");
}

#[test]
fn a_refused_charge_leaves_the_mount_usable() {
    let mut sp = Subpool::new(1, NO_LIMIT);
    assert!(sp.get_pages(1).is_ok());
    assert_eq!(sp.get_pages(1), Err(()));
    assert_eq!(sp.put_pages(1), 1);
    assert!(sp.get_pages(1).is_ok());
}

#[test]
fn a_minimum_size_reservation_absorbs_the_first_charges() {
    // min_size covers 3 pages, reserved globally at mount time, so the first
    // three charges need no further global reservation.
    let mut sp = Subpool::new(NO_LIMIT, 3);
    assert_eq!(sp.get_pages(1).unwrap().global_delta, 0);
    assert_eq!(sp.get_pages(1).unwrap().global_delta, 0);
    assert_eq!(sp.get_pages(1).unwrap().global_delta, 0);
    assert_eq!(sp.get_pages(1).unwrap().global_delta, 1, "past min_size the global pool pays");
}

#[test]
fn a_charge_larger_than_the_remaining_minimum_splits_the_difference() {
    let mut sp = Subpool::new(NO_LIMIT, 2);
    assert_eq!(sp.get_pages(5).unwrap().global_delta, 3);
    assert_eq!(sp.rsv_hpages, 0);
}

#[test]
fn releasing_below_the_minimum_size_takes_the_pages_back_into_the_reservation() {
    let mut sp = Subpool::new(NO_LIMIT, 2);
    let _ = sp.get_pages(2);
    // used stays 0 because max is unset, so every put restores the reservation.
    assert_eq!(sp.put_pages(2), 0);
    assert_eq!(sp.rsv_hpages, 2);
}

#[test]
fn a_mount_with_both_limits_reports_its_blocks() {
    let sp = Subpool::new(6, 2);
    assert_eq!(sp.blocks(), Some(6));
    assert_eq!(sp.blocks_free(), Some(6));
    let mut sp2 = sp;
    let _ = sp2.get_pages(4);
    assert_eq!(sp2.blocks_free(), Some(2));
}

#[test]
fn an_unlimited_maximum_reports_no_block_count() {
    let sp = Subpool::new(NO_LIMIT, 4);
    assert_eq!(sp.blocks(), None);
    assert_eq!(sp.blocks_free(), None);
}
