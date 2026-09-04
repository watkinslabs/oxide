//! Linux `task_struct::on_rq` state, including the migration bridge.

use core::sync::atomic::{AtomicU8, Ordering};

const OFF_RQ: u8 = 0;
const ON_RQ_QUEUED: u8 = 1;
const ON_RQ_MIGRATING: u8 = 2;

/// Atomic form of Linux's `TASK_ON_RQ_{QUEUED,MIGRATING}` integer.
pub struct TaskOnRq(AtomicU8);

impl TaskOnRq {
    pub const fn new(queued: bool) -> Self {
        Self(AtomicU8::new(if queued { ON_RQ_QUEUED } else { OFF_RQ }))
    }

    /// Compatibility predicate for callers asking whether any rq owns the
    /// task. Migration remains an owned rq transition. # C: O(1)
    pub fn load(&self, order: Ordering) -> bool { self.0.load(order) != OFF_RQ }

    /// Ordinary enqueue/dequeue publication. # C: O(1)
    pub fn store(&self, queued: bool, order: Ordering) {
        self.0.store(if queued { ON_RQ_QUEUED } else { OFF_RQ }, order);
    }

    /// Enqueue claim compatible with the former `AtomicBool::swap`: a task in
    /// MIGRATING is claimed by its destination and may be inserted there.
    pub fn swap(&self, queued: bool, order: Ordering) -> bool {
        let next = if queued { ON_RQ_QUEUED } else { OFF_RQ };
        self.0.swap(next, order) == ON_RQ_QUEUED
    }

    pub fn is_queued(&self, order: Ordering) -> bool {
        self.0.load(order) == ON_RQ_QUEUED
    }

    pub fn is_migrating(&self, order: Ordering) -> bool {
        self.0.load(order) == ON_RQ_MIGRATING
    }

    /// Source-rq bridge before publishing a new `task_cpu`. # C: O(1)
    pub fn begin_migration(&self) {
        self.0.store(ON_RQ_MIGRATING, Ordering::Release);
    }
}
