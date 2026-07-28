// Runqueue commit for plain host builds, where `sched::live` is compiled out
// (`sched/src/lib.rs:173`) and no runqueue exists to commit onto. This
// configuration builds the crate for lint/analysis only — it never schedules —
// so setattr.rs's validation and permission ladder stay reachable while the
// commit has nothing to act on. Sibling: commit_live.rs.

use alloc::sync::Arc;

/// No runqueue in this configuration; the class is already stored on the task.
/// # C: O(1)
pub fn set_class(_t: &Arc<sched::Task>, _c: sched::SchedClass) {}
