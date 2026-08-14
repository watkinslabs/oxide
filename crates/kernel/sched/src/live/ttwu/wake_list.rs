use alloc::sync::Arc;
#[cfg(any(test, feature = "hosted"))]
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::Task;
#[cfg(feature = "debug-watchdog")]
use crate::task::WakeDiagPhase;

#[cfg(feature = "debug-watchdog")]
use super::wake_diag_now_ns;

static WAKE_LISTS: [AtomicPtr<Task>; cpu::MAX_CPUS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; cpu::MAX_CPUS];

pub fn wake_list_push(cpu: u32, task: Arc<Task>) {
    let i = cpu as usize;
    if i >= cpu::MAX_CPUS { return; }
    if task.on_wake_list.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() { return; }
    #[cfg(feature = "debug-watchdog")]
    task.wake_diag_mark(WakeDiagPhase::Listed, wake_diag_now_ns());
    let raw = Arc::into_raw(task) as *mut Task;
    loop {
        let head = WAKE_LISTS[i].load(Ordering::Acquire);
        // SAFETY: raw owns the list reference until this cmpxchg publishes it.
        unsafe { (*raw).wake_next.store(head, Ordering::Relaxed); }
        if WAKE_LISTS[i].compare_exchange_weak(head, raw, Ordering::AcqRel, Ordering::Acquire).is_ok() { return; }
    }
}

pub(super) fn wake_list_take(cpu: u32) -> *mut Task {
    let i = cpu as usize;
    if i >= cpu::MAX_CPUS { return core::ptr::null_mut(); }
    WAKE_LISTS[i].swap(core::ptr::null_mut(), Ordering::AcqRel)
}

#[cfg(any(test, feature = "hosted"))]
pub fn wake_list_drain(cpu: u32) -> Vec<Arc<Task>> {
    let mut node = wake_list_take(cpu);
    let mut out = Vec::new();
    while !node.is_null() {
        // SAFETY: the detached chain has one list reference per node.
        let next = unsafe { (*node).wake_next.load(Ordering::Relaxed) };
        // SAFETY: this reclaims the list reference exactly once.
        let task = unsafe { Arc::from_raw(node as *const Task) };
        task.on_wake_list.store(false, Ordering::Release);
        #[cfg(feature = "debug-watchdog")]
        task.wake_diag_mark(WakeDiagPhase::Drained, wake_diag_now_ns());
        out.push(task);
        node = next;
    }
    out
}
