//! Freezer request, acknowledgement, refrigerator, and thaw transitions.

use core::sync::atomic::Ordering;

/// Whether the running task has acknowledged a freezer request. # C: O(1)
pub fn frozen_self() -> bool {
    super::schedule::current().map(|t| t.frozen.load(Ordering::Acquire)).unwrap_or(false)
}

/// cgroup v2 freezer (`cgroup.freeze=1`): request that `task` enter the
/// refrigerator at its next return-to-user checkpoint. Kernel threads are
/// excluded, as they are by Linux's cgroup v2 freezer.
/// # C: O(1) plus wake
pub fn freeze_task(task: &alloc::sync::Arc<crate::Task>) {
    freeze_task_for(task, crate::freeze_reason::CGROUP);
}

/// Request a safe-point freeze on behalf of `reason`. Request publication and
/// frozen acknowledgement are deliberately separate: an external task may
/// wake and nudge the target, but only the target may set `frozen` and schedule
/// away from a return-to-user or explicit freezable-kthread checkpoint.
/// # C: O(1) plus wake
pub fn freeze_task_for(task: &alloc::sync::Arc<crate::Task>, reason: u8) {
    let mut request = reason & crate::freeze_reason::ALL;
    if task.kernel_thread.load(Ordering::Acquire) {
        request &= !crate::freeze_reason::CGROUP;
    }
    if task.nofreeze.load(Ordering::Acquire)
        || task.suspend_task.load(Ordering::Acquire)
        || task.oom_victim.load(Ordering::Acquire)
    {
        request &= !crate::freeze_reason::SLEEP;
    }
    if request == 0 { return; }
    task.freeze_reasons.fetch_or(request, Ordering::AcqRel);
    // A job-control stop is already a safe boundary and already off-rq.
    if task.state() == crate::TaskState::Stopped {
        task.frozen.store(true, Ordering::Release);
        return;
    }
    // Linux uses a fake signal for userspace and a plain wake for an opted-in
    // kthread. The fake signal wakes interruptible, but not uninterruptible or
    // killable, waits; their ordinary completion reaches the checkpoint.
    if task.kernel_thread.load(Ordering::Acquire) { super::sigpend::wake_if_sleeping(task); }
    else { super::sigpend::signal_wake_up(task); }
}

/// Whether `task` owes a freezer checkpoint. # C: O(1)
pub fn freeze_requested(task: &crate::Task) -> bool {
    task.freeze_reasons.load(Ordering::Acquire) != 0
}

/// Enter the refrigerator at a caller-proven safe checkpoint and remain off
/// every runqueue until all independent freezer owners release their reasons.
///
/// # SAFETY: the caller is the running task on its own kernel stack, holds no
/// lock, and is at a return-to-user or explicit freezable-kthread checkpoint.
/// # C: O(schedule rounds until thaw)
/// # Sleeps: until every freezer owner releases the task
pub unsafe fn freeze_current_if_requested() -> bool {
    let Some(cur) = super::schedule::current() else { return false };
    if !freeze_requested(cur) { return false; }
    // TASK_FROZEN is a sleep state in Linux. Publish the equivalent before the
    // acknowledgement so thaw can use the ordinary Sleeping->Waking claim.
    cur.set_sleep_state(crate::WaitState::Uninterruptible);
    cur.frozen.store(true, Ordering::Release);
    // Close request-clear races on either side of the two stores above. A thaw
    // that ran before it observed `frozen` had nothing to wake. Whichever side
    // clears the acknowledgement owns the Sleeping transition: the target
    // repairs it locally only when its swap wins; otherwise thaw has already
    // claimed or queued the ordinary wake and the target must schedule into
    // that handoff instead of overwriting Waking.
    if !freeze_requested(cur) {
        if cur.frozen.swap(false, Ordering::AcqRel) {
            cur.set_state(crate::TaskState::Runnable);
        } else {
            // SAFETY: thaw owns the Sleeping wake; scheduling completes the
            // on_cpu handoff before this task can resume.
            unsafe { super::schedule(); }
        }
        return false;
    }
    while freeze_requested(cur) {
        // SAFETY: forwarded from this function's safe-checkpoint contract.
        unsafe { super::schedule(); }
    }
    cur.frozen.store(false, Ordering::Release);
    true
}

/// cgroup v2 thaw (`cgroup.freeze=0`): release the cgroup owner's request.
/// # C: O(N_cpus + log N)
pub fn unfreeze_task(task: &alloc::sync::Arc<crate::Task>) {
    unfreeze_task_for(task, crate::freeze_reason::CGROUP);
}

/// Release `reason`'s claim on `task` and wake its refrigerator once no
/// independent freezer owner remains. A stopped task remains stopped.
/// # C: O(N_cpus + log N)
pub fn unfreeze_task_for(task: &alloc::sync::Arc<crate::Task>, reason: u8) {
    let before = task.freeze_reasons.fetch_and(!reason, Ordering::AcqRel);
    if before & reason == 0 { return; }
    if before & !reason != 0 { return; }
    if !task.frozen.swap(false, Ordering::AcqRel) { return; }
    match task.state() {
        crate::TaskState::Sleeping => {
            // SAFETY: the freezer owns an Arc and this is the normal wake of
            // the refrigerator, including the on_cpu handoff race.
            unsafe { let _ = super::try_to_wake_up(alloc::sync::Arc::clone(task)); }
        }
        crate::TaskState::Runnable => {
            // A stopped task counts as safely frozen. SIGCONT can make it
            // Runnable while the enqueue chokepoint still rejects it; the
            // final thaw must complete that deferred placement.
            // SAFETY: a frozen Runnable task is off-rq; the Arc pins it across
            // select_task_rq and the on_cpu handoff.
            unsafe { super::ttwu::place_runnable(alloc::sync::Arc::clone(task), false); }
            crate::preempt::set_need_resched();
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::SchedClass;

    fn user(tid: u32) -> alloc::sync::Arc<crate::Task> {
        let task = alloc::sync::Arc::new(crate::Task::new(
            tid, "freeze-test", SchedClass::Normal { weight: 1024 }));
        task.kernel_thread.store(false, Ordering::Release);
        task.nofreeze.store(false, Ordering::Release);
        task
    }

    #[test]
    fn a_freeze_request_does_not_pretend_the_target_already_stopped() {
        let task = user(97_001);
        freeze_task_for(&task, crate::freeze_reason::SLEEP);
        assert!(freeze_requested(&task));
        assert!(!task.frozen.load(Ordering::Acquire),
            "an external freezer acknowledged work only the target can finish");
        assert_eq!(task.state(), crate::TaskState::Runnable);
    }

    #[test]
    fn a_stopped_task_is_already_at_a_safe_freezer_boundary() {
        let task = user(97_002);
        task.set_state(crate::TaskState::Stopped);
        freeze_task(&task);
        assert!(freeze_requested(&task));
        assert!(task.frozen.load(Ordering::Acquire));
    }

    #[test]
    fn one_thaw_cannot_release_another_freezers_stopped_task() {
        let task = user(97_005);
        task.set_state(crate::TaskState::Stopped);
        freeze_task(&task);
        freeze_task_for(&task, crate::freeze_reason::SLEEP);
        unfreeze_task_for(&task, crate::freeze_reason::SLEEP);
        assert!(task.frozen.load(Ordering::Acquire));
        assert_eq!(task.state(), crate::TaskState::Stopped);
        unfreeze_task(&task);
        assert!(!task.frozen.load(Ordering::Acquire));
        assert_eq!(task.state(), crate::TaskState::Stopped,
            "freezer thaw must not become SIGCONT");
    }

    #[test]
    fn cgroup_v2_does_not_freeze_a_kernel_thread() {
        let task = alloc::sync::Arc::new(crate::Task::new(
            97_003, "kfreeze-test", SchedClass::Normal { weight: 1024 }));
        freeze_task(&task);
        assert!(!freeze_requested(&task));
        assert!(!task.frozen.load(Ordering::Acquire));
    }

    #[test]
    fn thaw_before_acknowledgement_does_not_enqueue_the_running_target() {
        let task = user(97_004);
        freeze_task(&task);
        unfreeze_task(&task);
        assert!(!freeze_requested(&task));
        assert!(!task.frozen.load(Ordering::Acquire));
        assert!(!task.on_rq.load(Ordering::Acquire));
    }
}
