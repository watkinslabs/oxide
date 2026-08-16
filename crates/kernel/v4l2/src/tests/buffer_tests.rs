//! The buffer state machine and the transitions it must refuse.

use crate::vb2::state::{self, BufState};
use crate::uapi::flags;
use syscall::errno::Errno;

/// Every state, so a rule can be checked exhaustively rather than at the two
/// cases someone happened to think of.
const ALL: &[BufState] = &[
    BufState::Dequeued, BufState::InRequest, BufState::Preparing,
    BufState::Queued, BufState::Active, BufState::Done, BufState::Error,
];

#[test]
fn only_a_buffer_userspace_owns_may_be_queued() {
    for s in ALL {
        let admitted = state::may_queue(*s).is_ok();
        let should = matches!(s, BufState::Dequeued | BufState::InRequest);
        assert_eq!(admitted, should, "may_queue({s:?})");
        if !should { assert_eq!(state::may_queue(*s), Err(Errno::Einval)); }
    }
}

#[test]
fn preparing_admits_only_a_dequeued_buffer() {
    for s in ALL {
        let admitted = state::may_prepare(*s).is_ok();
        assert_eq!(admitted, *s == BufState::Dequeued, "may_prepare({s:?})");
    }
}

#[test]
fn completion_is_legal_only_from_active() {
    // A driver completing a buffer it holds is believed.
    assert_eq!(state::completion_target(BufState::Active, BufState::Done), BufState::Done);
    assert_eq!(state::completion_target(BufState::Active, BufState::Error), BufState::Error);
    assert_eq!(state::completion_target(BufState::Active, BufState::Queued), BufState::Queued);
    // A driver completing a buffer it does not hold is not: acting on the
    // report would put a buffer on the done list twice.
    for s in ALL.iter().filter(|s| **s != BufState::Active) {
        assert_eq!(state::completion_target(*s, BufState::Done), BufState::Error,
                   "completion from {s:?} must not be believed");
    }
    // Even from Active, a nonsensical target is refused.
    assert_eq!(state::completion_target(BufState::Active, BufState::Preparing), BufState::Error);
    assert_eq!(state::completion_target(BufState::Active, BufState::Dequeued), BufState::Error);
}

#[test]
fn cancellation_returns_every_state_to_the_caller() {
    for s in ALL {
        assert_eq!(state::cancelled_state(*s), BufState::Dequeued,
                   "a buffer left in {s:?} after cancel can never be recovered");
    }
}

#[test]
fn reported_flags_distinguish_the_states_an_application_acts_on() {
    assert_eq!(BufState::Dequeued.user_flags(), 0);
    assert_eq!(BufState::Queued.user_flags(), flags::BUF_FLAG_QUEUED);
    assert_eq!(BufState::Active.user_flags(), flags::BUF_FLAG_QUEUED);
    assert_eq!(BufState::Done.user_flags(), flags::BUF_FLAG_DONE);
    // A failed buffer is still done — losing it would leak it out of the pool,
    // so the failure rides as a flag on a buffer that comes back.
    assert_eq!(BufState::Error.user_flags(), flags::BUF_FLAG_DONE | flags::BUF_FLAG_ERROR);
    assert_eq!(BufState::InRequest.user_flags(), flags::BUF_FLAG_IN_REQUEST);
}

#[test]
fn done_and_in_flight_partition_the_states() {
    for s in ALL {
        assert!(!(s.is_done() && s.is_in_flight()),
                "{s:?} cannot be both completed and in flight");
    }
    assert!(BufState::Done.is_done());
    assert!(BufState::Error.is_done());
    assert!(BufState::Queued.is_in_flight());
    assert!(BufState::Active.is_in_flight());
    assert!(BufState::Preparing.is_in_flight());
    assert!(!BufState::Dequeued.is_done());
    assert!(!BufState::Dequeued.is_in_flight());
}
