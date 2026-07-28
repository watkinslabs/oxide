// Runqueue commit for builds where `sched::live` exists (kernel + test).
// Sibling: commit_absent.rs. Selected in sched_policy.rs.

use alloc::sync::Arc;

/// Commit the new class onto the runqueue — Linux `__setscheduler_class` +
/// re-enqueue under `task_rq_lock` (`kernel/sched/syscalls.c`).
/// # C: O(log n)
/// # Lk: takes the runqueue lock
pub fn set_class(t: &Arc<sched::Task>, c: sched::SchedClass) {
    sched::live::runqueue::set_class(t, c);
}
