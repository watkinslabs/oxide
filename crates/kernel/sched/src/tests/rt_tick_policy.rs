//! Linux `task_tick_rt` (`kernel/sched/rt.c`): the periodic tick must not
//! preempt a `SCHED_FIFO` task at all, and must preempt a `SCHED_RR` one only
//! when its quantum is exhausted AND a peer can take the CPU.
//!
//! The load-bearing assertion is the FIFO one. A test that merely checks "both
//! tasks eventually ran" passes an implementation that round-robins FIFO —
//! exactly the bug this covers, and one that inverts FIFO's defining guarantee
//! that it runs until it blocks or yields.

use crate::sched_enc::{rt_tick_wants_resched, RR_TIMESLICE_NS, RR_TIMESLICE_TICKS,
                       SCHED_FIFO, SCHED_RR};

/// The RR quantum on the reference scheduler is `100 * HZ / 1000` ticks, i.e.
/// 100 ms whatever HZ is, and `sched_rr_get_interval(2)` converts that SAME
/// tick count to a timespec. So there is exactly one number, and the enforced
/// quantum equals the reported one by construction.
const REFERENCE_RR_QUANTUM_NS: u64 = 100_000_000;

#[test]
fn the_enforced_rr_quantum_is_the_reported_one() {
    assert_eq!(RR_TIMESLICE_NS, REFERENCE_RR_QUANTUM_NS);
    // The tick count is the SAME quantum, not a second constant that happens
    // to be near it: enforcing 100 ticks of a 10 ms tick while reporting
    // 100 ms handed SCHED_RR tasks a 1 s slice.
    assert_eq!(RR_TIMESLICE_TICKS as u64 * crate::posix_clock::TICK_NSEC, RR_TIMESLICE_NS);
    assert_eq!(RR_TIMESLICE_TICKS, 10, "10 ms tick, 100 ms quantum");
}

#[test]
fn fifo_never_yields_to_the_tick() {
    assert!(!rt_tick_wants_resched(SCHED_FIFO, 1, true),
        "SCHED_FIFO must not be preempted by the tick even with a peer waiting");
    assert!(!rt_tick_wants_resched(SCHED_FIFO, 0, true),
        "SCHED_FIFO has no timeslice to exhaust");
}

#[test]
fn rr_yields_only_on_an_exhausted_quantum_with_a_peer() {
    assert!(!rt_tick_wants_resched(SCHED_RR, 5, true), "quantum remaining: keep running");
    assert!(rt_tick_wants_resched(SCHED_RR, 1, true), "exhausted with a peer: yield");
    // Linux checks `run_list.prev != run_list.next` before requeueing.
    assert!(!rt_tick_wants_resched(SCHED_RR, 1, false),
        "a sole RR task must not be requeued — pure overhead");
}

#[test]
fn fair_and_idle_still_preempt_every_tick() {
    assert!(rt_tick_wants_resched(0, 1, false), "SCHED_OTHER preempts per tick");
    assert!(rt_tick_wants_resched(5, 1, false), "SCHED_IDLE preempts per tick");
}
