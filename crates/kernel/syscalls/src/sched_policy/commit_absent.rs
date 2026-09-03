// Runqueue commit for plain host builds, where `sched::live` is compiled out
// (`sched/src/lib.rs:173`) and no runqueue exists to commit onto. This
// configuration builds the crate for lint/analysis only — it never schedules —
// so setattr.rs's validation and permission ladder stay reachable while the
// commit has nothing to act on. Sibling: commit_live.rs.

use alloc::sync::Arc;

/// No runqueue in this configuration; publish the validated task state directly.
/// # C: O(1)
pub fn set_class(t: &Arc<sched::Task>, c: sched::SchedClass, policy: u32,
                 clamp: sched::SchedUclamp, reset: bool) {
    t.set_sched_policy_controls(c, policy, clamp, reset);
}
