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

/// Move one task to an already-online scheduler group under TaskPi→runqueue.
pub fn set_task_group(task: &Arc<Task>, group_id: u64) {
    if task.sched.group_id() == group_id { return; }
    match super::super::rq_locate::task_rq_lock_with(
        &|cpu| unsafe { super::global_for(cpu) }, task)
    {
        super::super::rq_locate::StableTaskGuard::Owned(lock) => {
            let _change = super::super::rq_locate::SchedChange::from_lock(
                lock, task, super::super::schedule::change_clock_now());
            task.sched.store_group_id(group_id);
        }
        super::super::rq_locate::StableTaskGuard::OffRq(_pi) => {
            task.sched.store_group_id(group_id);
        }
    }
}
