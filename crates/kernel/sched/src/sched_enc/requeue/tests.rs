// Requeue position rules. These encode behaviour verified against the
// reference implementation's real-time class.

use super::*;
use crate::sched_enc::{SCHED_BATCH, SCHED_FIFO, SCHED_IDLE, SCHED_NORMAL, SCHED_RR};

#[test]
fn an_involuntarily_preempted_task_keeps_its_place() {
    assert_eq!(put_prev_pos(false), RequeuePos::Head);
}

#[test]
fn a_task_that_gave_up_its_turn_goes_behind_its_peers() {
    assert_eq!(put_prev_pos(true), RequeuePos::Tail);
}

#[test]
fn a_wakeup_never_jumps_the_queue() {
    assert_eq!(wake_pos(), RequeuePos::Tail);
}

#[test]
fn only_round_robin_rotates_on_the_tick() {
    // The defining difference between the two real-time policies: RR has a
    // quantum and rotates when it runs out, FIFO has none and never does.
    assert!(tick_gives_up_turn(SCHED_RR, 1, true));
    assert!(!tick_gives_up_turn(SCHED_FIFO, 1, true));
    for p in [SCHED_NORMAL, SCHED_BATCH, SCHED_IDLE] {
        assert!(!tick_gives_up_turn(p, 1, true), "policy {p} must not rotate");
    }
}

#[test]
fn round_robin_rotates_only_when_the_quantum_is_spent() {
    for left in 2..=100 {
        assert!(!tick_gives_up_turn(SCHED_RR, left, true), "slice_left {left}");
    }
    assert!(tick_gives_up_turn(SCHED_RR, 1, true));
    assert!(tick_gives_up_turn(SCHED_RR, 0, true));
}

#[test]
fn a_task_alone_at_its_priority_is_not_rotated() {
    assert!(!tick_gives_up_turn(SCHED_RR, 1, false));
    assert!(!tick_gives_up_turn(SCHED_RR, 0, false));
}

#[test]
fn a_fifo_task_preempted_repeatedly_never_loses_its_place() {
    // The regression this exists for: every involuntary preemption used to
    // push a FIFO task behind its peers, so N preemptions demoted it N times.
    for _ in 0..100 {
        assert!(!tick_gives_up_turn(SCHED_FIFO, 1, true));
        assert_eq!(put_prev_pos(false), RequeuePos::Head);
    }
}
