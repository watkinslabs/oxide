//! Allocation-free scheduler authorization hook table and dispatch.

use lsm_framework::{HookList, LsmId};
use sync::{SecurityPolicy as LockClass, Spinlock};

use super::{TaskSetNiceHook, TaskSetSchedulerHook};

/// Canonical scheduler authorization registry. Both hook tables share one
/// lock and each dispatch snapshots only fixed-size stack data.
#[derive(Copy, Clone)]
pub(super) struct TaskHooks {
    setnice: HookList<TaskSetNiceHook>,
    setscheduler: HookList<TaskSetSchedulerHook>,
}

impl TaskHooks {
    pub(super) const fn new() -> Self {
        Self { setnice: HookList::new(), setscheduler: HookList::new() }
    }

    pub(super) fn register_setnice(&mut self, lsm: LsmId, position: u16,
                                   hook: TaskSetNiceHook) {
        let _ = self.setnice.register(lsm, position, hook);
    }

    pub(super) fn register_setscheduler(&mut self, lsm: LsmId, position: u16,
                                        hook: TaskSetSchedulerHook) {
        let _ = self.setscheduler.register(lsm, position, hook);
    }
}

pub(super) fn setnice(
    registry: &Spinlock<TaskHooks, LockClass>, caller: &sched::Task, target: &sched::Task, nice: i32,
) -> Result<(), i64> {
    let hooks = { registry.lock().setnice };
    lsm_framework::call_first_decisive(&hooks, Ok(()),
        |hook| hook(caller, target, nice))
}

pub(super) fn setscheduler(
    registry: &Spinlock<TaskHooks, LockClass>, caller: &sched::Task, target: &sched::Task,
) -> Result<(), i64> {
    let hooks = { registry.lock().setscheduler };
    lsm_framework::call_first_decisive(&hooks, Ok(()), |hook| hook(caller, target))
}

#[cfg(test)]
#[path = "task_dispatch/tests.rs"]
mod tests;
