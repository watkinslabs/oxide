//! Scheduler PI state needed by the full futex hosted harness.

use alloc::sync::Arc;
use core::pin::Pin;

use crate::{pi_prio, runqueue, Task};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PiBlockedOn {
    pub lock_id: u64,
    pub waiter_id: u64,
    pub node: usize,
}

pub struct TaskPiState {
    waiters: pi_prio::PiWaiterTree,
    blocked: Option<PiBlockedOn>,
}

impl TaskPiState {
    pub const fn new() -> Self {
        Self { waiters: pi_prio::PiWaiterTree::new(), blocked: None }
    }

    pub fn blocked_on(&self) -> Option<PiBlockedOn> { self.blocked }

    pub fn set_blocked_on(&mut self, blocked: PiBlockedOn) {
        assert!(self.blocked.is_none());
        self.blocked = Some(blocked);
    }

    pub fn clear_blocked_on(&mut self, waiter_id: u64) {
        assert!(self.blocked.is_some_and(|blocked| blocked.waiter_id == waiter_id));
        self.blocked = None;
    }

    pub fn insert_waiter(&mut self, node: Pin<&mut pi_prio::PiTreeNode>) {
        self.waiters.insert(node);
    }

    pub fn remove_waiter(&mut self, node: Pin<&mut pi_prio::PiTreeNode>) {
        self.waiters.remove(node);
    }

    pub fn top_identity(&self) -> Option<(u64, pi_prio::PiDonorKey)> {
        self.waiters.first().map(|node| (node.waiter_id(), node.key()))
    }

    pub fn top_donor(&self) -> Option<(Arc<Task>, pi_prio::PiDonorKey)> {
        self.waiters.first().and_then(|node| node.donor().map(|task| (task, node.key())))
    }

    pub fn first_owned_lock(&self) -> Option<u64> {
        self.waiters.first().map(pi_prio::PiTreeNode::lock_id)
    }
}

pub mod rq_locate {
    use super::*;

    pub struct TaskRqGuard;
    pub enum StableTaskGuard<'a> {
        Owned(TaskRqGuard),
        OffRq(sync::IrqGuard<'a, TaskPiState, sync::TaskPi, sync::NoopIrq>),
    }

    pub struct SchedChange;
    impl SchedChange {
        pub(crate) fn from_lock(
            _lock: TaskRqGuard,
            _task: &Arc<Task>,
            _now: u64,
        ) -> Self {
            Self
        }
    }

    pub fn task_rq_lock_with<'a, F>(_get_rq: &F, task: &'a Task) -> StableTaskGuard<'a>
    where
        F: Fn(u32) -> Option<&'a runqueue::Runqueue>,
    {
        StableTaskGuard::OffRq(task.pi_lock.lock_irqsave::<sync::NoopIrq>())
    }

    pub fn __task_rq_lock_with<'a, F>(
        _get_rq: &F,
        _task: &'a Task,
        pi: sync::IrqGuard<'a, TaskPiState, sync::TaskPi, sync::NoopIrq>,
    ) -> StableTaskGuard<'a>
    where
        F: Fn(u32) -> Option<&'a runqueue::Runqueue>,
    {
        StableTaskGuard::OffRq(pi)
    }
}

pub mod schedule {
    pub fn change_clock_now() -> u64 { 0 }
}
