// Runqueue commit for builds where `sched::live` exists (kernel + test).
// Sibling: commit_absent.rs. Selected in sched_policy.rs.

use alloc::sync::Arc;

/// Commit the new class onto the runqueue — Linux `__setscheduler_class` +
/// re-enqueue under `task_rq_lock`.
///
/// Routed through `pi_boost::set_base_class`, not straight to the runqueue: a
/// task holding a PI futex may be running at a priority INHERITED from a
/// waiter, and writing the new class over that would be undone the moment the
/// mutex is released. The new value becomes the task's base class, takes effect
/// immediately when it outranks the inherited one, and otherwise applies at
/// deboost. A task with no boost takes the plain runqueue path.
/// # C: O(log n)
/// # Lk: takes the runqueue lock
pub fn apply(t: &Arc<sched::Task>, expected: (u32, u32), update: sched::SchedUpdate)
    -> sched::SchedUpdateResult {
    sched::live::runqueue::apply_update(t, expected, update)
}

pub fn reset(t: &Arc<sched::Task>, expected: (u32, u32), value: bool) -> bool {
    sched::live::runqueue::set_reset_if_policy(t, expected, value)
}

pub fn controls(t: &Arc<sched::Task>, expected: (u32, u32),
                clamp: sched::SchedUclamp, reset: bool) -> bool {
    sched::live::runqueue::set_controls_if_policy(t, expected, clamp, reset)
}
