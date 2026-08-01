// `SCHED_DEADLINE`: earliest-deadline-first scheduling with Constant Bandwidth
// Server enforcement, per `13§3`.
//
// Module manifest:
//   params.rs    — the static reservation (runtime/deadline/period), the
//                  fixed-point bandwidth pair derived from it, and the
//                  parameter-validation ladder.
//   cbs.rs       — the instance state machine: charge, throttle, replenish,
//                  wakeup rules. Pure functions; the whole point of the class.
//   bw.rs        — admission control: the admitted-bandwidth ledger and the
//                  overflow test that answers `EBUSY`.
//   entity.rs    — the per-task atomic home of both halves.
//   clock.rs     — the monotonic source, selected at the module boundary.
//   replenish.rs — throttled entities ordered by replenishment instant, folded
//                  into the hardware one-shot.
//   live.rs      — the runqueue/tick/yield wiring that applies `cbs.rs`.
//
// The ready set itself lives beside the other class runqueues in `dl.rs`, so
// `RunqueueInner` holds its three class trees together.

pub mod bw;
pub mod cbs;
pub mod clock;
pub mod entity;
pub mod params;

pub mod live;
pub mod replenish;

#[cfg(test)]
#[path = "deadline/tests/live.rs"] mod live_tests;

pub use cbs::{dl_time_before, Charged, DlSched};
pub use entity::DlEntity;
pub use params::{checkparam_dl, to_ratio, DlParams, BW_SHIFT, BW_UNIT, DL_PERIOD_MAX_NS,
                 DL_PERIOD_MIN_NS, DL_SCALE, FLAG_DL_OVERRUN, FLAG_RECLAIM, FLAG_SUGOV,
                 MAX_BW, SCHED_DL_FLAGS};

/// May `task` join a class ready tree right now? A throttled deadline entity
/// may not: its budget for this instance is spent, and queueing it anyway is
/// exactly the "validated then ignored" shape that turns a real-time class back
/// into a priority label.
/// # C: O(1)
pub fn enqueue_admits(task: &crate::task::Task) -> bool {
    !matches!(task.sched_class(), crate::task::SchedClass::Deadline) || !task.dl.is_throttled()
}

/// The CPU set the deadline class schedules over, and the set every admitted
/// reservation is booked against. All online CPUs: one class, one ledger, one
/// span, so a reservation cannot be admitted against one set and honoured
/// against another.
///
/// Before bring-up publishes a mask the span is the boot CPU alone — NOT every
/// possible CPU. Guessing high would let the first reservations be admitted
/// against capacity that does not exist yet.
/// # C: O(1)
pub fn span() -> u64 {
    let m = cpu::smp::online_mask();
    if m == 0 { 1 } else { m }
}

/// Ordering between two deadline entities. STRICT: an equal deadline never
/// preempts and never reorders, so a set of equal-deadline tasks runs in
/// arrival order instead of thrashing.
/// # C: O(1)
pub fn dl_entity_preempt(a_deadline: u64, a_special: bool, b_deadline: u64) -> bool {
    a_special || dl_time_before(a_deadline, b_deadline)
}
