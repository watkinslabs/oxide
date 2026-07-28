//! Wait-expiry timers — Linux `schedule_hrtimeout_range` / `hrtimer` for every
//! blocking wait with a timeout (`nanosleep`, `epoll_wait`, `poll`, `select`,
//! futex timeouts, `SO_RCVTIMEO`, `mq_timedsend`, `semtimedop`, …).
//!
//! Module manifest:
//!   `model` — soft/hard range arithmetic, the deadline-ordered queue, and the
//!             slack policy. Pure, hosted-tested, no `Task` and no lock.
//!   `queue` — the live queue, the next-event cache the one-shot programmer
//!             reads, arm/disarm, and the hard-IRQ sweep.
//!
//! Wiring: `WaitList::park_with_deadline` (and the futex fast path) arm here;
//! `sched::timers::next_interrupt_deadline` folds the earliest expiry into the
//! hardware one-shot; the arch timer dispatchers call `expire_now` on every
//! CPU. See `13§11` for the wake path this feeds.

pub mod model;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
mod queue;
#[cfg(test)]
mod tests;

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub use queue::{arm, arm_current, disarm, disarm_current, earliest_hard_ns, expire, expire_now,
    select_estimate_accuracy, task_slack_ns};
pub use model::{estimate_accuracy, hard_expiry, fold_wait_expiry, MAX_SLACK_NS};
