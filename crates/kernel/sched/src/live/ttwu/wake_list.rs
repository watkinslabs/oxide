use alloc::sync::Arc;
#[cfg(any(test, feature = "hosted"))]
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

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
/// Safe diagnostic cardinality. Producers increment after winning the
/// per-task list claim; the exclusive drainer decrements before releasing the
/// list reference. Diagnostics never dereference concurrently reclaimed nodes.
static WAKE_COUNT: [AtomicU32; cpu::MAX_CPUS] =
    [const { AtomicU32::new(0) }; cpu::MAX_CPUS];

/// Publish to a target selected active by an enclosing placement RCU reader.
/// Caller holds TaskPi and has already published `task.cpu`; this primitive
/// never selects or rewrites ownership. CPU-down cannot pass its placement
/// grace period until this list insertion completes.
pub(super) fn wake_list_push_selected(cpu: u32, task: Arc<Task>) -> bool {
    let i = cpu as usize;
    if i >= cpu::MAX_CPUS { return false; }
    if task.on_wake_list.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() { return false; }
    WAKE_COUNT[i].fetch_add(1, Ordering::AcqRel);
    // Claim the batch before publishing the node.  The post-publication check
    // below closes the target's clear-between-claim-and-link race.
    let mut kick = !WAKE_PENDING[i].swap(true, Ordering::AcqRel);
    #[cfg(feature = "debug-watchdog")]
    task.wake_diag_mark(WakeDiagPhase::Listed, wake_diag_now_ns());
    let raw = Arc::into_raw(task) as *mut Task;
    loop {
        let head = WAKE_LISTS[i].load(Ordering::Acquire);
        // SAFETY: raw owns the list reference until this cmpxchg publishes it.
        unsafe { (&(*raw)).wake_next.store(head, Ordering::Relaxed); }
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

/// Re-publish one detached node while retaining its original wake ownership
/// and CPU-down count. The target callback uses this when `on_cpu` has not yet
/// cleared; no second producer claim or generation is minted.
pub(super) fn wake_list_requeue_selected(cpu: u32, task: Arc<Task>) -> bool {
    let i = cpu as usize;
    hal::kassert!(i < cpu::MAX_CPUS, "wake-list requeue CPU out of range");
    hal::kassert!(task.on_wake_list.load(Ordering::Acquire),
        "wake-list requeue lost detached ownership");
    let mut kick = !WAKE_PENDING[i].swap(true, Ordering::AcqRel);
    let raw = Arc::into_raw(task) as *mut Task;
    loop {
        let head = WAKE_LISTS[i].load(Ordering::Acquire);
        // SAFETY: raw retains the detached list reference until publication.
        unsafe { (&(*raw)).wake_next.store(head, Ordering::Relaxed); }
        if WAKE_LISTS[i].compare_exchange_weak(head, raw,
            Ordering::AcqRel, Ordering::Acquire).is_ok() {
            if !WAKE_PENDING[i].load(Ordering::Acquire) {
                kick |= !WAKE_PENDING[i].swap(true, Ordering::AcqRel);
            }
            return kick;
        }
    }
}

#[cfg(test)]
pub(crate) fn wake_list_push_selected_for_test(cpu: u32, task: Arc<Task>) -> bool {
    let _placement = sync::rcu_read_lock();
    wake_list_push_selected(cpu, task)
}

pub(super) fn wake_list_take(cpu: u32) -> *mut Task {
    let i = cpu as usize;
    if i >= cpu::MAX_CPUS { return core::ptr::null_mut(); }
    WAKE_LISTS[i].swap(core::ptr::null_mut(), Ordering::AcqRel)
}

/// Release one node claimed from `cpu`'s detached list. # C: O(1)
pub(super) fn wake_list_release(cpu: u32, task: &Task) {
    let i = cpu as usize;
    hal::kassert!(i < cpu::MAX_CPUS, "wake-list release CPU out of range");
    hal::kassert!(task.on_wake_list.swap(false, Ordering::AcqRel),
        "wake-list drain released an unclaimed task");
    let before = WAKE_COUNT[i].fetch_sub(1, Ordering::AcqRel);
    hal::kassert!(before != 0, "wake-list diagnostic count underflow");
}

/// Diagnostic snapshot of one CPU's deferred-wake state: whether the target
/// still owes an activation batch (`ttwu_pending`) and how many tasks are
/// claimed for it. A non-zero count beside a cleared batch latch, or any count
/// that does not fall, is a wake list nobody is draining. # C: O(1)
pub fn wake_list_debug(cpu: u32) -> (bool, u32) {
    let i = cpu as usize;
    if i >= cpu::MAX_CPUS { return (false, 0); }
    (WAKE_PENDING[i].load(Ordering::Acquire), WAKE_COUNT[i].load(Ordering::Acquire))
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
        let next = unsafe { (&(*node)).wake_next.load(Ordering::Relaxed) };
        // SAFETY: this reclaims the list reference exactly once.
        let task = unsafe { Arc::from_raw(node as *const Task) };
        wake_list_release(cpu, &task);
        #[cfg(feature = "debug-watchdog")]
        task.wake_diag_mark(WakeDiagPhase::Drained, wake_diag_now_ns());
        out.push(task);
        node = next;
    }
    let _ = wake_list_finish(cpu);
    out
}
