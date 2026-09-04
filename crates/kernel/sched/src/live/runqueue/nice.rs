//! Stable nice mutation after the configured policy is locked.

use alloc::sync::Arc;

use crate::{SchedClass, Task};

/// Change Linux nice under one stable TaskPi/runqueue transaction. # C: O(contention + log N)
pub fn set_nice(task: &Arc<Task>, nice: i8) {
    if task.nice_value() == nice { return; }
    #[cfg(test)]
    crate::tests::interleave::point("set_nice:before-lock");
    match super::super::rq_locate::task_rq_lock_with(
        &|cpu| unsafe { super::global_for(cpu) }, task)
    {
        super::super::rq_locate::StableTaskGuard::Owned(lock) => {
            #[cfg(test)]
            crate::tests::interleave::point("set_nice:locked");
            if matches!(task.normal_sched_class(), SchedClass::Rt { .. }
                | SchedClass::Deadline)
            {
                task.sched.store_nice(nice);
            } else {
                let _change = super::super::rq_locate::SchedChange::from_lock(
                    lock, task, super::super::schedule::change_clock_now());
                task.sched.store_nice(nice);
            }
        }
        super::super::rq_locate::StableTaskGuard::OffRq(_pi) => {
            #[cfg(test)]
            crate::tests::interleave::point("set_nice:locked");
            task.sched.store_nice(nice);
        }
    }
    super::super::pi_boost::notify_waiter_change(task);
}

/// Update scheduler-owned task-group identity and shares under the same
/// TaskPi→runqueue transaction as nice/class changes. Queued fair entities are
/// removed and reinserted so their EEVDF request and parent-group key agree.
/// # C: O(contention + log N)
pub fn set_group_shares(task: &Arc<Task>, group_id: u64, shares: u32) {
    set_group_shares_with_map(
        &|cpu| {
            // SAFETY: global runqueues are permanently allocated after installation.
            unsafe { super::global_for(cpu) }
        }, task, group_id, shares);
}

fn set_group_shares_with_map<'a, F>(get_rq: &F, task: &'a Arc<Task>,
                                    group_id: u64, shares: u32)
where F: Fn(u32) -> Option<&'a super::Runqueue> {
    if task.sched.group_id() == group_id && task.sched.group_shares() == shares { return; }
    match super::super::rq_locate::task_rq_lock_with(
        get_rq, task)
    {
        super::super::rq_locate::StableTaskGuard::Owned(lock) => {
            let _change = super::super::rq_locate::SchedChange::from_lock(
                lock, task, super::super::schedule::change_clock_now());
            task.sched.store_group_id(group_id);
            task.sched.store_group_shares(shares);
        }
        super::super::rq_locate::StableTaskGuard::OffRq(_pi) => {
            task.sched.store_group_id(group_id);
            task.sched.store_group_shares(shares);
        }
    }
}

#[cfg(test)]
/// Hosted real-runqueue form of the canonical group mutation. # C: O(contention + log N)
pub(crate) fn set_group_shares_with<'a, F>(get_rq: &F, task: &'a Arc<Task>,
                                           group_id: u64, shares: u32)
where F: Fn(u32) -> Option<&'a super::Runqueue> {
    set_group_shares_with_map(get_rq, task, group_id, shares);
}
