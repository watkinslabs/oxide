use alloc::sync::Arc;
#[cfg(any(test, feature = "hosted"))]
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use crate::Task;
#[cfg(feature = "debug-watchdog")]
use crate::task::WakeDiagPhase;

#[cfg(feature = "debug-watchdog")]
use super::wake_diag_now_ns;

static WAKE_LISTS: [AtomicPtr<Task>; cpu::MAX_CPUS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; cpu::MAX_CPUS];
/// Linux `rq->ttwu_pending`: one remote wake notification covers every task
/// linked until the target has activated that batch.  Without this latch every
/// timer expiry sends a synchronous IPI; a burst can leave the sending CPU
/// spinning in ICR delivery while all already-queued work remains unreachable.
static WAKE_PENDING: [AtomicBool; cpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; cpu::MAX_CPUS];

/// Link `task` and report whether the caller owns the one required target
/// reschedule notification. # C: O(1) amortized CAS.
pub fn wake_list_push(cpu: u32, task: Arc<Task>) -> bool {
    let i = cpu as usize;
    if i >= cpu::MAX_CPUS { return false; }
    if task.on_wake_list.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() { return false; }
    // Claim the batch before publishing the node.  The post-publication check
    // below closes the target's clear-between-claim-and-link race.
    let mut kick = !WAKE_PENDING[i].swap(true, Ordering::AcqRel);
    #[cfg(feature = "debug-watchdog")]
    task.wake_diag_mark(WakeDiagPhase::Listed, wake_diag_now_ns());
    let raw = Arc::into_raw(task) as *mut Task;
    loop {
        let head = WAKE_LISTS[i].load(Ordering::Acquire);
        // SAFETY: raw owns the list reference until this cmpxchg publishes it.
        unsafe { (*raw).wake_next.store(head, Ordering::Relaxed); }
        if WAKE_LISTS[i].compare_exchange_weak(head, raw, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            // The target may have observed an empty list and cleared its batch
            // latch while this producer was between the claim above and this
            // publication.  Reclaim that notification duty in that case.
            if !WAKE_PENDING[i].load(Ordering::Acquire) {
                kick |= !WAKE_PENDING[i].swap(true, Ordering::AcqRel);
            }
            return kick;
        }
    }
}

pub(super) fn wake_list_take(cpu: u32) -> *mut Task {
    let i = cpu as usize;
    if i >= cpu::MAX_CPUS { return core::ptr::null_mut(); }
    WAKE_LISTS[i].swap(core::ptr::null_mut(), Ordering::AcqRel)
}

/// Finish one target-side activation batch.  A concurrent producer which
/// linked while the batch was owned suppressed its IPI, so leave the target
/// with a local reschedule request when work appeared before this clear.
/// # C: O(1)
pub(super) fn wake_list_finish(cpu: u32) -> bool {
    let i = cpu as usize;
    if i >= cpu::MAX_CPUS { return false; }
    WAKE_PENDING[i].store(false, Ordering::Release);
    !WAKE_LISTS[i].load(Ordering::Acquire).is_null()
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
    let _ = wake_list_finish(cpu);
    out
}
