extern crate alloc;

use alloc::sync::Arc;
use crate::task::{SchedClass, SchedPolicy, Task};
use core::sync::atomic::Ordering;

pub(super) fn rt(tid: u32, prio: u8) -> Arc<Task> {
    Arc::new(Task::new(tid, "rt", SchedClass::Rt { prio, policy: SchedPolicy::Fifo }))
}

pub(super) fn normal(tid: u32, vruntime: u64, weight: u32) -> Arc<Task> {
    let t = Arc::new(Task::new(tid, "normal", SchedClass::Normal { weight }));
    t.vruntime.store(vruntime, Ordering::Release);
    t
}

pub(super) fn idle(tid: u32) -> Arc<Task> {
    Arc::new(Task::new(tid, "idle", SchedClass::Idle))
}

// Hosted runqueue, waiters, and task registry state all share CPU 0 and
// process-global statics; one lock must cover every test touching that state.
pub(crate) fn hosted_global_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

// Registry-specific spelling retained for existing test modules.
pub(crate) fn registry_test_lock() -> std::sync::MutexGuard<'static, ()> { hosted_global_test_lock() }
