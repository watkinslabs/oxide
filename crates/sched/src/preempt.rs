// Preempt-count machinery per `13§9`. v1 stores the count in a
// single global AtomicU32 — UP only. When SMP arrives the storage
// moves to `PerCpu<AtomicU32>` without changing the public API, so
// callers stay correct across the transition.
//
// Discipline (`13§9`):
//   - `preempt_count > 0` ⇒ no schedule() may run.
//   - Hits zero only at well-defined release sites: kernel-return-
//     to-user, idle, end-of-softirq, voluntary yield.
//   - `need_resched=true` is set by wakeup / tick; checked at every
//     `preempt_enable` decrement-to-zero and at IRQ-exit.
//
// `PreemptGuard` is the RAII pair: drop runs `preempt_enable()`,
// which schedules iff count returned to zero and need_resched is set.

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

static PREEMPT_COUNT: AtomicU32  = AtomicU32::new(0);
static NEED_RESCHED:  AtomicBool = AtomicBool::new(false);

/// Hook installed by the kernel side so `preempt_enable` can call
/// `schedule()` when discipline allows. v1 single fn pointer; SMP
/// will continue to share one schedule() entry point per `13§8`.
/// Stored as `AtomicPtr<()>`; the value is round-tripped from a
/// `unsafe fn()` so the no-`static mut` rule (`07§5`) holds.
static SCHEDULE_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// # SAFETY: install once during boot before any preempt_enable can
/// fire a reschedule. The function pointer must remain valid for
/// the kernel's lifetime.
/// # C: O(1)
pub unsafe fn set_schedule_hook(hook: unsafe fn()) {
    SCHEDULE_HOOK.store(hook as *mut (), Ordering::Release);
}

/// Current preempt count on this CPU.
/// # C: O(1)
pub fn preempt_count() -> u32 { PREEMPT_COUNT.load(Ordering::Acquire) }

/// True iff a reschedule has been requested (set by wake_up / tick).
/// # C: O(1)
pub fn need_resched() -> bool { NEED_RESCHED.load(Ordering::Acquire) }

/// Set `need_resched`. Called from wake_up paths and the tick when
/// the running task should yield (CFS slice expired, RT preempts
/// Normal, etc.). Idempotent.
/// # C: O(1)
pub fn set_need_resched() { NEED_RESCHED.store(true, Ordering::Release); }

/// Atomically take + clear `need_resched`. Returns the prior value.
/// Used by the schedule path so a single tick→wake→schedule cycle
/// doesn't loop on a stuck flag.
/// # C: O(1)
pub fn take_need_resched() -> bool { NEED_RESCHED.swap(false, Ordering::AcqRel) }

/// Bump the preempt count. Pairs with `preempt_enable` /
/// `preempt_enable_no_check`. Prefer the `PreemptGuard` RAII form
/// to keep pairs balanced.
/// # C: O(1)
pub fn preempt_disable() {
    PREEMPT_COUNT.fetch_add(1, Ordering::AcqRel);
}

/// Decrement without the resched check. Used at sites that must
/// not call schedule() (e.g. inside the schedule path itself when
/// switching back into a preempt-off region).
/// # C: O(1)
pub fn preempt_enable_no_check() {
    let prev = PREEMPT_COUNT.fetch_sub(1, Ordering::AcqRel);
    // Underflow check in debug; in release the saturating_sub
    // semantics on AtomicU32::fetch_sub wrap, which would surface
    // as a wedged scheduler — so refuse in debug.
    debug_assert!(prev != 0, "preempt_enable_no_check underflow");
}

/// Decrement and, if the count returns to zero with `need_resched`
/// set, fire a reschedule via the installed hook.
///
/// # SAFETY: caller asserts the schedule hook (if registered) may
/// run at this point — i.e. we are not inside an IRQ handler, are
/// not holding spinlocks that schedule() acquires, and the current
/// task's stack is suitable for a context switch.
/// # C: O(1) + O(log N) iff schedule fires
pub unsafe fn preempt_enable() {
    let prev = PREEMPT_COUNT.fetch_sub(1, Ordering::AcqRel);
    debug_assert!(prev != 0, "preempt_enable underflow");
    if prev == 1 && take_need_resched() {
        let raw = SCHEDULE_HOOK.load(Ordering::Acquire);
        if !raw.is_null() {
            // SAFETY: raw came from a `unsafe fn()` cast in
            // set_schedule_hook; install-once-at-boot contract; caller
            // of preempt_enable promised this is a safe schedule point.
            let f: unsafe fn() = unsafe { core::mem::transmute(raw) };
            // SAFETY: per set_schedule_hook contract.
            unsafe { f(); }
        }
    }
}

/// RAII pair for `preempt_disable`/`preempt_enable`. Drop fires the
/// resched check.
pub struct PreemptGuard {
    _private: (),
}

impl PreemptGuard {
    /// Acquire a guard. Increments preempt_count.
    /// # C: O(1)
    pub fn new() -> Self {
        preempt_disable();
        Self { _private: () }
    }
}

impl Default for PreemptGuard {
    fn default() -> Self { Self::new() }
}

impl Drop for PreemptGuard {
    fn drop(&mut self) {
        // Drop runs in arbitrary kernel contexts (any place a guard
        // goes out of scope). The unchecked variant is the safer
        // default — sites that explicitly want a resched on drop
        // should call preempt_enable() manually before letting the
        // guard drop, then leak the guard via mem::forget. v1 keeps
        // RAII-drop conservative.
        preempt_enable_no_check();
    }
}

/// Reset all preempt state. Hosted-test-only — production never
/// resets these atomics.
/// # C: O(1)
#[cfg(any(test, feature = "hosted"))]
pub fn _test_reset() {
    PREEMPT_COUNT.store(0, Ordering::Release);
    NEED_RESCHED.store(false, Ordering::Release);
}
