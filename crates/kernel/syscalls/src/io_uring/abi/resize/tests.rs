use super::*;
use crate::io_uring_abi::layout::{prepare_resize, MAX_ENTRIES, NO_SQ_ARRAY};
use crate::io_uring_abi::uapi::*;

fn params(flags: u32, entries: u32) -> Params {
    let mut p = Params::from_bytes(&[0u8; PARAMS_SIZE]);
    p.flags = flags;
    p.sq_entries = entries;
    p
}

/// Only a ring built with `IORING_SETUP_DEFER_TASKRUN` may be resized.
#[test]
fn resize_needs_defer_taskrun() {
    let mut p = params(0, 64);
    assert_eq!(prepare_resize(&mut p, 0), Err(Errno::Einval));
    assert_eq!(prepare_resize(&mut p, IORING_SETUP_SINGLE_ISSUER), Err(Errno::Einval));
    let ring = IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SINGLE_ISSUER;
    assert!(prepare_resize(&mut params(0, 64), ring).is_ok());
}

/// The request may restate only the two sizing flags.
#[test]
fn resize_request_flags_are_bounded() {
    let ring = IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SINGLE_ISSUER;
    for bad in [IORING_SETUP_SINGLE_ISSUER, IORING_SETUP_DEFER_TASKRUN,
                IORING_SETUP_NO_SQARRAY, IORING_SETUP_SUBMIT_ALL] {
        assert_eq!(prepare_resize(&mut params(bad, 8), ring), Err(Errno::Einval),
                   "flag {bad:#x} must not be restatable");
    }
    assert!(prepare_resize(&mut params(IORING_SETUP_CLAMP, 8), ring).is_ok());
    let mut p = params(IORING_SETUP_CQSIZE, 8);
    p.cq_entries = 32;
    assert_eq!(prepare_resize(&mut p, ring).unwrap().cq_entries, 32);
}

/// The layout flags come from the RING, not the request: a ring built without
/// an SQ index array keeps having none after a resize, even though the request
/// may not name that flag.
#[test]
fn resize_inherits_the_layout_flags_from_the_ring() {
    let ring = IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_NO_SQARRAY;
    let mut p = params(0, 8);
    let g = prepare_resize(&mut p, ring).unwrap();
    assert_eq!(g.sq_array_off, NO_SQ_ARRAY);
    assert_eq!(p.flags & IORING_SETUP_NO_SQARRAY, IORING_SETUP_NO_SQARRAY);

    let ring = IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SINGLE_ISSUER;
    let g = prepare_resize(&mut params(0, 8), ring).unwrap();
    assert_ne!(g.sq_array_off, NO_SQ_ARRAY);
}

/// A resize is admitted through the same entries ladder as setup.
#[test]
fn resize_uses_the_setup_entries_ladder() {
    let ring = IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SINGLE_ISSUER;
    assert_eq!(prepare_resize(&mut params(0, 0), ring), Err(Errno::Einval));
    assert_eq!(prepare_resize(&mut params(0, MAX_ENTRIES + 1), ring), Err(Errno::Einval));
    let mut p = params(IORING_SETUP_CLAMP, MAX_ENTRIES + 1);
    assert_eq!(prepare_resize(&mut p, ring).unwrap().sq_entries, MAX_ENTRIES);
    // Non-power-of-two rounds up, exactly as at setup.
    assert_eq!(prepare_resize(&mut params(0, 5), ring).unwrap().sq_entries, 8);
}

/// The refusal is decided from the head/tail pairs, before anything is copied.
#[test]
fn a_ring_too_small_for_what_is_pending_is_refused() {
    assert_eq!(admit_pending(0, 8, 8), Ok(8));
    assert_eq!(admit_pending(0, 9, 8), Err(Errno::Eoverflow));
    // Empty and full-drained rings carry nothing, whatever the counters read.
    assert_eq!(admit_pending(1000, 1000, 1), Ok(0));
    // Wraparound: the counters are free-running, so only the difference counts.
    assert_eq!(admit_pending(u32::MAX - 1, 2, 8), Ok(4));
    assert_eq!(admit_pending(u32::MAX - 1, 2, 2), Err(Errno::Eoverflow));
}

/// Growing a ring re-lays every pending entry at its new slot.
#[test]
fn sq_entries_move_to_their_new_slots() {
    // No index array: the counter masks straight into the SQE array.
    assert_eq!(sq_move(5, 8, 4, None), SqMove::Copy { dst: 5, src: 1, array: None });
    assert_eq!(sq_move(9, 4, 8, None), SqMove::Copy { dst: 1, src: 1, array: None });
    // With an index array the SQE comes from wherever the array points, and
    // the new array records the destination, because that is where the SQE
    // has been put.
    assert_eq!(sq_move(5, 8, 4, Some(3)), SqMove::Copy { dst: 5, src: 3, array: Some(5) });
    // An index naming no SQE stays "no entry" instead of aliasing slot 0.
    assert_eq!(sq_move(5, 8, 4, Some(4)), SqMove::NoEntry { dst: 5 });
    assert_eq!(sq_move(5, 8, 4, Some(u32::MAX)), SqMove::NoEntry { dst: 5 });
}

/// Shrinking a CQ ring keeps the completions' order under the new mask.
#[test]
fn cq_entries_move_to_their_new_slots() {
    assert_eq!(cq_move(0, 4, 8), (0, 0));
    assert_eq!(cq_move(6, 4, 8), (2, 6));
    assert_eq!(cq_move(6, 16, 8), (6, 6));
    // Consecutive completions stay consecutive in the destination.
    let slots: alloc::vec::Vec<u32> = (3..7).map(|i| cq_move(i, 8, 4).0).collect();
    assert_eq!(slots, alloc::vec![3, 4, 5, 6]);
}
