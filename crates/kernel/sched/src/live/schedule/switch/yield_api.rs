use super::*;
use super::round::schedule_once;

/// Linux `schedule`: repeat scheduling rounds until the resumed task has no
/// pending reschedule request.  A request can arrive while this task was
/// off-CPU; returning from one round and ignoring that task-local flag strands
/// the request until some unrelated safe point.  Blocking and yielding callers
/// use this public loop, while the IRQ-return path owns its distinct
/// IRQ-enable/disable loop around [`schedule_once`].
///
/// # SAFETY: caller satisfies the scheduler safe-point contract.
/// # C: O(log N) per scheduling round
#[track_caller]
pub unsafe fn schedule() {
    loop {
        // SAFETY: forwarded from this function's scheduler safe-point contract.
        unsafe { schedule_once(false); }
        if !crate::preempt::should_resched() { break; }
    }
}

/// Cooperative voluntary yield. Calls `schedule()` then parks the
/// CPU on `hlt`/`wfi` until the next IRQ.
///
/// The trailing halt opens the IRQ window that a BUSY-yield caller (one
/// that stays Runnable — recvmsg/accept/sendto spin-waiting for device
/// data) depends on to receive that data, so
/// this form is for those callers. A caller that has already PARKED
/// (marked itself Sleeping via a wait list) must instead use
/// [`park_yield`], which does NOT halt: a parked task must not idle the
/// CPU, because the per-CPU idle task provides the halt/IRQ-window and the
/// scheduler must be free to run every other ready task back-to-back. See
/// [`park_yield`] for why that distinction is load-bearing for wake
/// latency. # C: O(log N) + O(1) ctxsw + O(IRQ_latency)
/// # SAFETY: per `schedule()`.
/// # Ctx: process|kthread; preempt-off; IRQs-on
#[track_caller]
pub unsafe fn tick_yield() {
    // SAFETY: caller satisfies `schedule()`'s contract (process / kthread context, preempt-off, single-CPU); delegated wholesale.
    unsafe { schedule(); }
    // SAFETY: cooperative yield owns a lock-free process-context idle window.
    unsafe { crate::live::schedule::irq::halt_enabled(); }
}

/// Linux `sched_yield(2)`: class-specific yield then schedule. # C: O(log N)
/// # SAFETY: per `schedule()`.
/// # Ctx: process|kthread; preempt-off
#[track_caller]
pub unsafe fn sched_yield() {
    if let Some(rq) = global() {
        // SAFETY: current_ref borrow is bounded to this preempt-off syscall path.
        unsafe { rq.current_ref() }.yield_pending.store(true, Ordering::Release);
    }
    // SAFETY: caller satisfies `schedule()`'s contract; yield marker consumed before requeue.
    unsafe { schedule(); }
}

/// Yield after a task has already published Sleeping on a wait list. The
/// caller immediately rechecks its condition when scheduled again. CPU-idle
/// code, not a blocking wait, owns the architectural halt; otherwise a wake
/// that wins before this scheduling round completes is delayed until a later
/// interrupt.
/// # SAFETY: caller has marked itself Sleeping on a wait list and owns the
/// post-park schedule per `schedule()`'s contract; must re-check its
/// condition (and re-park) after this returns.
/// # C: O(log N) + O(1) ctxsw
/// # Ctx: process|kthread; preempt-off; caller Sleeping
#[track_caller]
pub unsafe fn park_yield() {
    // SAFETY: caller satisfies `schedule()`'s contract and has parked Sleeping; delegated wholesale.
    unsafe { schedule(); }
}

