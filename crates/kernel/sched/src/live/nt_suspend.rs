//! Native NT thread suspension at the scheduler-owned return checkpoint.

use alloc::sync::Arc;

use crate::{Task, TaskState, WaitState};

/// Release the final NT suspend depth through the scheduler wake owner. # C: O(N_cpus + log N)
pub fn resume_task(task: &Arc<Task>) {
    if task.nt_creation_pending.load(core::sync::atomic::Ordering::Acquire) { return; }
    if task.nt_suspend_count.load(core::sync::atomic::Ordering::Acquire) != 0 { return; }
    if task.nt_suspend_ack.load(core::sync::atomic::Ordering::Acquire)
        || task.nt_wake_pending.load(core::sync::atomic::Ordering::Acquire) {
        // SAFETY: the task Arc pins the target; this owns the state-to-rq transition.
        unsafe { super::ttwu::wake_nt_suspended(Arc::clone(task)); }
    } else if task.claim_nt_initial_wake() {
        // CREATE_SUSPENDED tasks are published Runnable but intentionally stay
        // off-rq until their first final resume.
        // SAFETY: the Runnable-to-Waking claim excludes concurrent birth/resume
        // placement; this Arc pins the task through the scheduler activation.
        unsafe { super::ttwu::place_runnable(Arc::clone(task), false); }
    }
}

/// Consume a pending NT suspension only at a return-to-user safe point. # C: O(schedule rounds)
/// # SAFETY: caller is the running task on its own stack, with no lock held.
pub unsafe fn suspend_current_if_requested() -> bool {
    let Some(cur) = super::current() else { return false };
    if !cur.nt_suspend_requested() { return false; }
    cur.set_sleep_state(WaitState::Uninterruptible);
    cur.nt_suspend_ack.store(true, core::sync::atomic::Ordering::Release);
    if !cur.nt_suspend_requested() {
        cur.nt_suspend_ack.store(false, core::sync::atomic::Ordering::Release);
        let _ = cur.cas_state(TaskState::Sleeping, TaskState::Runnable);
        return false;
    }
    while cur.nt_suspend_requested() {
        // SAFETY: the task published its off-rq state at this safe checkpoint.
        unsafe { super::schedule(); }
    }
    cur.nt_suspend_ack.store(false, core::sync::atomic::Ordering::Release);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_predicate_is_false_without_a_request() {
        let task = Arc::new(Task::new(98_423, "nt-checkpoint", crate::SchedClass::Normal { weight: 1024 }));
        assert!(!task.nt_suspend_requested());
    }
}
