use crate::Task;
use crate::live::{rq_locate::task_rq_lock_with, runqueue::Runqueue};

pub(super) fn take(task: &Task) -> bool {
    take_with(task, &|cpu| {
        // SAFETY: installed runqueues remain alive throughout timer servicing.
        unsafe { crate::live::runqueue::global_for(cpu) }
    })
}

fn take_with<'a>(task: &'a Task, get_rq: &impl Fn(u32) -> Option<&'a Runqueue>) -> bool {
    // No write for an inert entity. A concurrently arriving overrun remains
    // pending for the next scan; consumption rechecks under canonical ownership.
    if !task.sched.dl.sched().overrun { return false; }
    let _owner = task_rq_lock_with(get_rq, task);
    task.sched.dl.take_overrun()
}

#[cfg(test)]
#[path = "tests/overrun.rs"]
mod tests;
