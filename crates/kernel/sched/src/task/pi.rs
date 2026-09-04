//! Task-owned priority-inheritance state protected by `Task::pi_lock`.

use alloc::sync::Arc;
use core::pin::Pin;

use super::Task;
use crate::pi_prio::{PiDonorKey, PiTreeNode, PiWaiterTree};

/// Identity of the one rtmutex waiter on which this task is blocked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PiBlockedOn {
    pub lock_id: u64,
    pub waiter_id: u64,
    pub node: usize,
}
/// Linux `task_struct::{pi_waiters,pi_blocked_on}` under `p->pi_lock`.
pub struct TaskPiState {
    pi_waiters: PiWaiterTree,
    pi_blocked_on: Option<PiBlockedOn>,
}

impl TaskPiState {
    pub const fn new() -> Self {
        Self { pi_waiters: PiWaiterTree::new(), pi_blocked_on: None }
    }

    pub fn blocked_on(&self) -> Option<PiBlockedOn> { self.pi_blocked_on }

    pub fn set_blocked_on(&mut self, blocked: PiBlockedOn) {
        assert!(self.pi_blocked_on.is_none(), "task acquired a second PI blocked-on edge");
        self.pi_blocked_on = Some(blocked);
    }

    pub fn clear_blocked_on(&mut self, waiter_id: u64) {
        assert!(self.pi_blocked_on.is_some_and(|blocked| blocked.waiter_id == waiter_id),
            "PI blocked-on clear does not name this task's waiter");
        self.pi_blocked_on = None;
    }

    pub fn insert_waiter(&mut self, node: Pin<&mut PiTreeNode>) { self.pi_waiters.insert(node); }
    pub fn remove_waiter(&mut self, node: Pin<&mut PiTreeNode>) { self.pi_waiters.remove(node); }
    pub fn waiter_count(&self) -> usize { self.pi_waiters.len() }

    pub fn top_identity(&self) -> Option<(u64, PiDonorKey)> {
        self.pi_waiters.first().map(|node| (node.waiter_id(), node.key()))
    }

    pub fn top_donor(&self) -> Option<(Arc<Task>, PiDonorKey)> {
        self.pi_waiters.first().and_then(|node| node.donor().map(|task| (task, node.key())))
    }

    pub fn first_owned_lock(&self) -> Option<u64> {
        self.pi_waiters.first().map(PiTreeNode::lock_id)
    }
}
