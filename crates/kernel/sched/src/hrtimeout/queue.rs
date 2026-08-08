// Kernel glue for the wait-expiry model: the one live queue, the lock-free
// next-event cache the one-shot programmer reads, and the hard-IRQ sweep.
// Policy lives in `model.rs` (hosted-tested); this file only binds it to
// `Task`, the clock and the wake path.
//
// Before B1460 a timed park stamped `Task::wakeup_deadline_ns` and nothing
// else. Its only consumer was `tick_wake_expired`, a registry walk registered
// as a 100 ms periodic on the `ktimers` kthread, self-throttled to 100 ms, on a
// kthread that parks 100 ms per loop — so EVERY kernel timeout had a ~100 ms
// floor, and `next_interrupt_deadline()` (which programs the hardware one-shot)
// never saw a wait deadline at all. `epoll_wait(.., 1)` and `nanosleep(1ms)`
// both blocked ~100 ms.

use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Hrtimeout as HrtimeoutClass, Spinlock};

use crate::Task;
use super::model::{estimate_accuracy, hard_expiry, DeadlineQueue};

/// Armed wait expiries, ordered by hard expiry. Taken irqsave: the hard timer
/// IRQ sweeps it while process-context parks insert into it.
///
/// One global queue rather than Linux's per-CPU `hrtimer_cpu_base`: the
/// existing wall-timer queue behind `EARLIEST_WALL_NS` is already global and
/// every CPU's `rearm_local` already programs from it, so a second, differently
/// scoped structure would be a second policy for the same question. The sweep
/// runs on every CPU and takes each expiry under the lock, so exactly one CPU
/// wakes each waiter.
static ARMED: Spinlock<DeadlineQueue<Weak<Task>>, HrtimeoutClass> =
    Spinlock::new(DeadlineQueue::new());

/// Earliest armed HARD expiry, published for `next_interrupt_deadline()` to
/// read without taking `ARMED` — Linux `cpu_base->expires_next`, which
/// `hrtimer_reprogram` also consults lock-free. `u64::MAX` = nothing armed.
static EARLIEST_HARD_NS: AtomicU64 = AtomicU64::new(u64::MAX);

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
macro_rules! armed_lock {
    () => { ARMED.lock_irqsave::<hal_x86_64::X86IrqGate>() };
}
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
macro_rules! armed_lock {
    () => { ARMED.lock_irqsave::<hal_aarch64::ArmIrqGate>() };
}
#[cfg(not(target_os = "oxide-kernel"))]
macro_rules! armed_lock {
    () => { ARMED.lock() };
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn now_ns() -> u64 { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn now_ns() -> u64 { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }
#[cfg(not(target_os = "oxide-kernel"))]
fn now_ns() -> u64 { 0 }

/// Linux keeps `timer_slack_ns` at 0 for the whole time a task is
/// SCHED_FIFO/RR/DEADLINE, so every slack consumer reads 0 for a real-time
/// task without testing the policy itself.
/// The write sites hold that invariant here too; this reader states the
/// invariant it depends on rather than re-deriving it.
/// # C: O(1)
pub fn task_slack_ns(task: &Task) -> u64 { task.timer_slack_ns.load(Ordering::Acquire) }

/// Linux `select_estimate_accuracy` for an absolute monotonic deadline —
/// poll(2), select(2) and epoll_wait(2) coalesce far more aggressively than the
/// flat 50 us nanosleep/futex slack, up to 100 ms on a long timeout.
/// # C: O(1)
pub fn select_estimate_accuracy(deadline_ns: u64) -> u64 {
    let Some(cur) = crate::live::current() else { return 0 };
    estimate_accuracy(deadline_ns.saturating_sub(now_ns()), task_slack_ns(cur),
        cur.nice.load(Ordering::Relaxed) > 0)
}

/// Arm `task`'s wait expiry at `soft_ns`, allowing it to fire as late as
/// `soft_ns + slack_ns` — Linux `hrtimer_start_range_ns`. `soft_ns == 0` means
/// "no timeout" and cancels instead. Reprograms this CPU's one-shot, which is
/// what makes a sub-tick timeout land on time rather than at the next
/// accounting tick.
/// # C: O(N armed)
/// # Ctx: process
pub fn arm(task: &Arc<Task>, soft_ns: u64, slack_ns: u64) {
    if soft_ns == 0 { disarm(task); return; }
    let hard_ns = hard_expiry(soft_ns, slack_ns);
    // Published before the queue insert: the sweep treats an entry whose task
    // no longer names this soft expiry as stale, so the store must be visible
    // to any CPU that can reach the entry.
    task.wakeup_deadline_ns.store(soft_ns, Ordering::Release);
    {
        let mut g = armed_lock!();
        g.arm(task.tid, soft_ns, hard_ns, Arc::downgrade(task));
        EARLIEST_HARD_NS.store(g.earliest_hard_ns(), Ordering::Release);
    }
    crate::timers::reprogram_local();
}

/// As [`arm`] for the running task. `futex` publishes its wait deadline from a
/// `&Task` it already holds rather than through a `WaitList`.
/// # C: O(N armed)
/// # Ctx: process
pub fn arm_current(soft_ns: u64, slack_ns: u64) {
    let Some(task) = current_arc() else { return };
    arm(&task, soft_ns, slack_ns);
}

/// Cancel `task`'s wait expiry — Linux `hrtimer_cancel`. # C: O(N armed)
pub fn disarm(task: &Task) {
    task.wakeup_deadline_ns.store(0, Ordering::Release);
    let mut g = armed_lock!();
    if g.disarm(task.tid).is_some() {
        EARLIEST_HARD_NS.store(g.earliest_hard_ns(), Ordering::Release);
    }
}

/// As [`disarm`] for the running task. # C: O(N armed)
pub fn disarm_current() {
    if let Some(task) = crate::live::current() { disarm(task); }
}

/// Earliest armed HARD expiry, or `u64::MAX`. Lock-free — read from the timer
/// IRQ on every reprogram. # C: O(1)
pub fn earliest_hard_ns() -> u64 { EARLIEST_HARD_NS.load(Ordering::Acquire) }

/// Wake every task whose SOFT expiry has passed — Linux
/// `__hrtimer_run_queues`, called from the hard timer IRQ on every CPU.
///
/// The lock is dropped before each wake: `ttwu_deferred` is the IRQ-safe wake
/// path (it pushes to the lock-free per-CPU wake list) but it must not run with
/// a leaf lock held that a process-context park also takes.
/// # C: O(due)
/// # Ctx: timer IRQ
pub fn expire(now: u64) {
    loop {
        let entry = {
            let mut g = armed_lock!();
            let popped = g.pop_soft_due(now);
            if popped.is_some() { EARLIEST_HARD_NS.store(g.earliest_hard_ns(), Ordering::Release); }
            popped
        };
        let Some(entry) = entry else { return };
        // A `Weak` upgrade rather than `registry::lookup`: the walk this
        // replaces took the registry lock in hard-IRQ context and scanned every
        // live task to find one. A dead task is simply skipped.
        let Some(task) = entry.payload.upgrade() else { continue };
        // Another waker reached this task first (`ttwu` clears the deadline) or
        // it re-parked on a different one. Either way this expiry is stale and
        // waking on it would be a spurious wake the waiter must re-park from.
        if task.wakeup_deadline_ns.load(Ordering::Acquire) != entry.soft_ns { continue; }
        // SAFETY: timer-IRQ wake site; the upgraded Arc keeps `task` alive across the call.
        unsafe { crate::live::ttwu::ttwu_deferred(task); }
    }
}

/// [`expire`] against the current monotonic time — the arch timer dispatchers'
/// entry point. # C: O(due)
/// # Ctx: timer IRQ
pub fn expire_now() { expire(now_ns()); }

/// The running task as an owned `Arc`, for the callers that hold only a
/// `&'static Task`.
fn current_arc() -> Option<Arc<Task>> {
    let rq = crate::live::runqueue::global()?;
    let raw = rq.current.load(Ordering::Acquire);
    if raw.is_null() { return None; }
    // SAFETY: `rq.current` is a live `Arc<Task>` pointer after install_global; the bump is consumed by the matching `from_raw` below, leaving the count balanced.
    unsafe { Arc::increment_strong_count(raw); }
    // SAFETY: consumes exactly the strong count bumped above.
    Some(unsafe { Arc::from_raw(raw) })
}
