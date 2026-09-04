//! Explicit fixture-only scheduler state setup for downstream hosted tests.

use crate::{SchedClass, SchedUclamp, Task};

/// # C: O(1)
pub fn set_nice(task: &Task, nice: i8) { task.set_nice_value(nice); }

/// # C: O(1)
pub fn set_normal_policy(task: &Task, class: SchedClass, policy: u32) {
    task.set_normal_sched_class_policy(class, policy);
}

/// # C: O(1)
pub fn set_reset_on_fork(task: &Task, reset: bool) {
    task.set_sched_reset_on_fork(reset);
}

/// # C: O(1)
pub fn set_policy_controls(task: &Task, class: SchedClass, policy: u32,
                           clamp: SchedUclamp, reset: bool) {
    task.set_sched_policy_controls(class, policy, clamp, reset);
}

/// # C: O(1)
pub fn set_deadline_state(task: &Task, state: &crate::deadline::DlSched) {
    task.test_set_sched_deadline_state(state);
}

/// # C: O(1)
pub fn set_deadline_params(task: &Task, params: &crate::DlParams) {
    task.test_set_sched_deadline_params(params);
}

/// # C: O(1)
pub fn set_rt_timeslice(task: &Task, ticks: u32) {
    task.test_set_sched_rt_timeslice(ticks);
}

/// # C: O(1)
pub fn set_deadline_exec_start(task: &Task, now: u64) {
    crate::deadline::live::set_next_task_dl(task, now);
}

/// # C: O(1)
pub fn charge_deadline(task: &Task, now: u64) -> crate::deadline::Charged {
    crate::deadline::live::update_curr_dl(task, now)
}
