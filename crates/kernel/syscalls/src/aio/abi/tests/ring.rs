// Completion-ring index arithmetic, including the wrap cases and the
// untrusted-head folding that stops a userspace-written index from addressing
// outside the mapped region.

use crate::aio_abi::ring::*;

#[test]
fn indices_from_the_shared_ring_are_folded_into_range() {
    assert_eq!(wrap(0, 8), 0);
    assert_eq!(wrap(7, 8), 7);
    assert_eq!(wrap(8, 8), 0);
    assert_eq!(wrap(u32::MAX, 8), u32::MAX % 8);
    // A zero-slot ring can never address a slot.
    assert_eq!(wrap(5, 0), 0);
}

#[test]
fn tail_advances_and_wraps_at_the_slot_count() {
    assert_eq!(advance_tail(0, 4), 1);
    assert_eq!(advance_tail(2, 4), 3);
    assert_eq!(advance_tail(3, 4), 0);
    // A tail already out of range folds to 0 rather than running away.
    assert_eq!(advance_tail(9, 4), 0);
}

#[test]
fn available_count_in_the_simple_and_wrapped_cases() {
    assert_eq!(avail(0, 3, 8), 3);
    assert_eq!(avail(6, 2, 8), 4); // wrapped: 2 + 8 - 6
    assert_eq!(avail(7, 0, 8), 1);
}

#[test]
fn tail_meeting_head_counts_as_a_full_ring_for_waiters() {
    // This is the wake condition for a waiter blocked on min_nr when the
    // completion that wrapped the ring lands, so it must not read as empty.
    assert_eq!(avail(3, 3, 8), 8);
    assert_eq!(avail(0, 0, 8), 8);
}

#[test]
fn empty_ring_yields_no_work_and_leaves_head_alone() {
    let (chunks, head) = read_plan(5, 5, 8, 4);
    assert!(chunks.is_empty());
    assert_eq!(head, 5);
    // A zero or negative request likewise reaps nothing.
    assert_eq!(read_plan(0, 4, 8, 0).0.len(), 0);
    assert_eq!(read_plan(0, 4, 8, -1).0.len(), 0);
    // A zero-slot ring is inert.
    assert!(read_plan(0, 1, 0, 4).0.is_empty());
}

#[test]
fn contiguous_reap_is_one_run() {
    let (chunks, head) = read_plan(1, 5, 8, 10);
    assert_eq!(chunks, alloc::vec![(1, 4)]);
    assert_eq!(head, 5);
}

#[test]
fn wrapped_reap_splits_at_the_end_of_the_ring() {
    // head 6, tail 2 in an 8-slot ring: slots 6,7 then 0,1.
    let (chunks, head) = read_plan(6, 2, 8, 10);
    assert_eq!(chunks, alloc::vec![(6, 2), (0, 2)]);
    assert_eq!(head, 2);
}

#[test]
fn reap_is_clamped_to_the_requested_count() {
    let (chunks, head) = read_plan(6, 2, 8, 3);
    assert_eq!(chunks, alloc::vec![(6, 2), (0, 1)]);
    assert_eq!(head, 1);
    let (chunks, head) = read_plan(6, 2, 8, 1);
    assert_eq!(chunks, alloc::vec![(6, 1)]);
    assert_eq!(head, 7);
}

#[test]
fn an_out_of_range_user_head_cannot_escape_the_ring() {
    // Userspace owns `head` and may write anything there.
    let (chunks, head) = read_plan(u32::MAX, 2, 8, 10);
    for &(start, count) in &chunks {
        assert!(start < 8);
        assert!(start as u64 + count as u64 <= 8);
    }
    assert!(head < 8);
}

#[test]
fn every_reaped_slot_is_inside_the_ring_for_all_index_pairs() {
    const NR: u32 = 5;
    for head in 0..NR {
        for tail in 0..NR {
            for want in 0..(NR as i64 + 2) {
                let (chunks, new_head) = read_plan(head, tail, NR, want);
                let total: u32 = chunks.iter().map(|&(_, c)| c).sum();
                assert!(total as i64 <= want.max(0));
                assert!(new_head < NR);
                for &(start, count) in &chunks {
                    assert!(count > 0);
                    assert!(start + count <= NR);
                }
                // A non-empty ring with room to reap always makes progress.
                if head != tail && want > 0 { assert!(total > 0); }
            }
        }
    }
}

#[test]
fn a_full_reap_drains_the_ring_exactly_once() {
    let nr = 8;
    let (chunks, head) = read_plan(3, 3u32.wrapping_sub(1) % nr, nr, 100);
    let total: u32 = chunks.iter().map(|&(_, c)| c).sum();
    assert_eq!(total, nr - 1);
    assert_eq!(head, 2);
}
