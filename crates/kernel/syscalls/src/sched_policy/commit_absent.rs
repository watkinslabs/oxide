// Runqueue commit for plain host builds, where `sched::live` is compiled out
// (`sched/src/lib.rs:173`) and no runqueue exists to commit onto. This
// configuration builds the crate for lint/analysis only — it never schedules —
// so setattr.rs's validation and permission ladder stay reachable while the
// commit has nothing to act on. Sibling: commit_live.rs.

use alloc::sync::Arc;

/// No runqueue in this configuration; publish the validated task state directly.
/// # C: O(1)
pub fn apply(t: &Arc<sched::Task>, expected: (u32, u32), update: sched::SchedUpdate)
    -> sched::SchedUpdateResult {
    t.apply_sched_update_checked(expected, update)
}

pub fn reset(t: &Arc<sched::Task>, expected: (u32, u32), value: bool) -> bool {
    t.set_sched_reset_if_generation(expected, value)
}

pub fn controls(t: &Arc<sched::Task>, expected: (u32, u32),
                clamp: sched::SchedUclamp, reset: bool) -> bool {
    t.set_sched_controls_if_generation(expected, clamp, reset)
}
