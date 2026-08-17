//! Handing an id out, taking it back, and the counts that must add up.

use super::*;

/// A table big enough to hold more ids than the cache will keep. # C: O(1)
const MAX_NID: u32 = 5_000;
/// Available memory, in pages, at which the cache has room for what these
/// tests put in it. # C: O(1)
const ROOMY: u64 = 1 << 20;

/// A cache holding `n` ids, the lowest usable one first. # C: O(n log n)
fn holding(n: u32) -> FreeNids {
    let mut f = FreeNids::new(0, MAX_NID);
    for nid in RESERVED_NODE_NUM..RESERVED_NODE_NUM + n {
        assert!(f.add(nid, MAX_NID, true, Some(true)));
    }
    f
}

// --------------------------------------------------------- what may be an id

#[test]
fn an_id_below_the_reserved_floor_is_never_offered() {
    let mut f = FreeNids::new(0, MAX_NID);
    for nid in 0..RESERVED_NODE_NUM {
        assert!(!f.add(nid, MAX_NID, true, Some(true)), "nid {nid}");
    }
    assert_eq!(f.free_count(), 0);
}

#[test]
fn an_id_at_or_past_the_tables_end_is_never_offered() {
    let mut f = FreeNids::new(0, MAX_NID);
    assert!(!f.add(MAX_NID, MAX_NID, true, Some(true)));
    assert!(!f.add(MAX_NID + 1, MAX_NID, true, Some(true)));
    assert_eq!(f.free_count(), 0);
}

// ------------------------------------------------------------- the order out

#[test]
fn the_oldest_free_id_is_the_one_handed_out() {
    let mut f = holding(4);
    let out: alloc::vec::Vec<u32> = (0..4).map(|_| f.alloc().unwrap()).collect();
    assert_eq!(out, alloc::vec![3, 4, 5, 6]);
    assert_eq!(f.alloc(), None);
}

#[test]
fn an_id_given_back_goes_to_the_end_of_the_queue() {
    let mut f = holding(3);
    let first = f.alloc().unwrap();
    assert_eq!(first, 3);
    f.alloc_failed(first, ROOMY);
    assert_eq!(f.free_order(), alloc::vec![4, 5, 3]);
    assert_eq!(f.alloc(), Some(4));
}

#[test]
fn an_id_that_stuck_is_forgotten() {
    let mut f = holding(2);
    let nid = f.alloc().unwrap();
    assert_eq!(f.alloc_count(), 1);
    f.alloc_done(nid);
    assert_eq!(f.alloc_count(), 0);
    assert_eq!(f.state_of(nid), None);
    assert_eq!(f.free_order(), alloc::vec![4]);
}

#[test]
fn an_id_in_a_callers_hands_is_never_handed_out_again() {
    let mut f = holding(2);
    let a = f.alloc().unwrap();
    let b = f.alloc().unwrap();
    assert_ne!(a, b);
    assert_eq!(f.state_of(a), Some(NidState::Prealloc));
    assert_eq!(f.alloc(), None);
}

// ----------------------------------------------------- what the volume has left

#[test]
fn handing_one_out_and_giving_it_back_moves_the_remaining_count_by_exactly_one() {
    let mut f = holding(2);
    let before = f.available_nids();
    let nid = f.alloc().unwrap();
    assert_eq!(f.available_nids(), before - 1);
    f.alloc_failed(nid, ROOMY);
    assert_eq!(f.available_nids(), before);
}

#[test]
fn an_id_that_stuck_does_not_give_the_count_back() {
    let mut f = holding(2);
    let before = f.available_nids();
    let nid = f.alloc().unwrap();
    f.alloc_done(nid);
    assert_eq!(f.available_nids(), before - 1);
}

#[test]
fn nothing_is_handed_out_when_the_volume_has_no_ids_left() {
    let mut f = FreeNids::new(0, 0);
    assert!(f.add(3, MAX_NID, true, Some(true)));
    assert_eq!(f.free_count(), 1);
    assert_eq!(f.alloc(), None);
}

#[test]
fn an_add_outside_a_build_raises_what_the_volume_has_left() {
    let mut f = FreeNids::new(0, 10);
    assert!(f.add(3, MAX_NID, false, None));
    assert_eq!(f.available_nids(), 11);
}

#[test]
fn an_add_during_a_build_does_not_raise_what_the_volume_has_left() {
    let mut f = FreeNids::new(0, 10);
    assert!(f.add(3, MAX_NID, true, Some(true)));
    assert_eq!(f.available_nids(), 10);
}

// ----------------------------------------------------------- the build checks

#[test]
fn a_build_refuses_an_id_the_table_says_is_in_use() {
    let mut f = FreeNids::new(0, MAX_NID);
    assert!(!f.add(3, MAX_NID, true, Some(false)));
    assert_eq!(f.free_count(), 0);
}

#[test]
fn a_build_reports_an_id_it_already_holds_as_free_without_holding_it_twice() {
    let mut f = holding(1);
    assert!(f.add(3, MAX_NID, true, Some(true)));
    assert_eq!(f.free_count(), 1);
    assert_eq!(f.free_order(), alloc::vec![3]);
}

#[test]
fn a_build_reports_an_id_in_a_callers_hands_as_not_free() {
    let mut f = holding(1);
    let nid = f.alloc().unwrap();
    assert!(!f.add(nid, MAX_NID, true, Some(true)));
    assert_eq!(f.state_of(nid), Some(NidState::Prealloc));
    assert_eq!(f.free_count(), 0);
}

#[test]
fn an_add_outside_a_build_does_not_disturb_an_id_in_a_callers_hands() {
    let mut f = holding(1);
    let nid = f.alloc().unwrap();
    assert!(f.add(nid, MAX_NID, false, None));
    assert_eq!(f.state_of(nid), Some(NidState::Prealloc));
    assert_eq!(f.free_count(), 0);
}

// ------------------------------------------------------------------ forgetting

#[test]
fn removing_an_id_leaves_one_in_a_callers_hands_alone() {
    let mut f = holding(2);
    let held = f.alloc().unwrap();
    f.remove(held);
    assert_eq!(f.state_of(held), Some(NidState::Prealloc));
    f.remove(4);
    assert_eq!(f.state_of(4), None);
    assert_eq!(f.free_count(), 0);
}

// --------------------------------------------------------------------- shrink

#[test]
fn a_shrink_at_or_below_the_ceiling_drops_nothing() {
    let mut f = holding(MAX_FREE_NIDS);
    assert_eq!(f.shrink(100), 0);
    assert_eq!(f.free_count(), MAX_FREE_NIDS);
}

#[test]
fn a_shrink_stops_at_the_ceiling() {
    let mut f = holding(MAX_FREE_NIDS + 50);
    assert_eq!(f.shrink(1_000), 50);
    assert_eq!(f.free_count(), MAX_FREE_NIDS);
}

#[test]
fn a_shrink_drops_no_more_than_it_was_asked_for() {
    let mut f = holding(MAX_FREE_NIDS + 50);
    assert_eq!(f.shrink(20), 20);
    assert_eq!(f.free_count(), MAX_FREE_NIDS + 30);
}

#[test]
fn a_shrink_drops_the_oldest_first() {
    let mut f = holding(MAX_FREE_NIDS + 3);
    f.shrink(2);
    let left = f.free_order();
    assert_eq!(left[0], RESERVED_NODE_NUM + 2);
}

#[test]
fn a_shrink_leaves_ids_in_callers_hands_alone() {
    let mut f = holding(MAX_FREE_NIDS + 10);
    let held = f.alloc().unwrap();
    let dropped = f.shrink(1_000);
    assert_eq!(f.alloc_count(), 1);
    assert_eq!(f.state_of(held), Some(NidState::Prealloc));
    assert_eq!(dropped, 9);
}

// ------------------------------------------------------------ the memory budget

#[test]
fn the_budget_flips_at_the_threshold_and_back() {
    let f = FreeNids::new(0, MAX_NID);
    assert!(!f.available_free_memory(399));
    assert!(f.available_free_memory(400));
}

#[test]
fn raising_the_threshold_moves_the_budget() {
    let mut f = FreeNids::new(0, MAX_NID);
    assert!(!f.available_free_memory(399));
    f.ram_thresh = 2;
    assert!(f.available_free_memory(399));
}

#[test]
fn a_cache_holding_more_needs_more_room_for_it() {
    let big = holding(MAX_FREE_NIDS);
    let small = FreeNids::new(0, MAX_NID);
    let avail = 400;
    assert!(small.available_free_memory(avail));
    assert!(!big.available_free_memory(avail));
}

#[test]
fn giving_an_id_back_with_no_room_drops_it_but_returns_the_count() {
    let mut f = holding(2);
    let before = f.available_nids();
    let nid = f.alloc().unwrap();
    f.alloc_failed(nid, 0);
    assert_eq!(f.state_of(nid), None);
    assert_eq!(f.alloc_count(), 0);
    assert_eq!(f.available_nids(), before);
}

// ------------------------------------------------------------------ the ceiling

#[test]
fn a_thin_cache_asks_for_a_walk_and_a_full_one_does_not() {
    let thin = holding(1);
    assert!(thin.need_build());
    let full = holding(crate::uapi::NAT_ENTRY_PER_BLOCK as u32);
    assert!(!full.need_build());
}

#[test]
fn the_footprint_grows_with_what_is_held() {
    let none = FreeNids::new(0, MAX_NID);
    let some = holding(10);
    assert_eq!(none.mem_bytes(), 0);
    assert!(some.mem_bytes() >= 10 * ENTRY_BYTES as u64);
}

#[test]
fn the_two_tallies_are_kept_apart() {
    assert_eq!(NID_STATES, 2);
    assert_ne!(NidState::Free.index(), NidState::Prealloc.index());
}
