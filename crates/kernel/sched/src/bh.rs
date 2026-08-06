//! Bottom-half (softirq) control, per Linux `kernel/softirq.c`. Built on the
//! per-CPU `preempt_count` softirq field (`crate::preempt`): `local_bh_disable`
//! raises it so process context can exclude softirqs (the basis of
//! `spin_lock_bh`); the softirq drain marks `in_serving_softirq` across the
//! handlers so re-entry is impossible without a separate flag.
//!
//! `do_softirq` is THE drain entry point — the IRQ-tail (lapic/gic) and
//! ksoftirqd call it; it brackets the `softirq::run_pending` core (the
//! `__do_softirq` restart gate) in softirq accounting and bails when already
//! in a bottom-half/IRQ context (Linux `in_interrupt()` guard, replacing the
//! old per-CPU `IN_PROGRESS` bool).
use crate::preempt::{
    self, SOFTIRQ_DISABLE_OFFSET, SOFTIRQ_OFFSET,
};

struct SchedHandlerAccounting;

unsafe extern "C" fn run_pending_on_irq_stack() {
    // SAFETY: the caller holds SOFTIRQ_OFFSET across this callback, so handler
    // accounting and the restart gate have the same contract as the former
    // inline task-stack call.
    unsafe { softirq::run_pending_accounted::<SchedHandlerAccounting>(); }
}

unsafe fn do_softirq_own_stack() {
    #[cfg(target_arch = "aarch64")]
    // SAFETY: SOFTIRQ_OFFSET prevents scheduling and re-entry for the whole
    // callback, satisfying the architecture trampoline's non-sleep contract.
    unsafe {
        hal_aarch64::call_on_irq_stack(run_pending_on_irq_stack);
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: SOFTIRQ_OFFSET prevents scheduling and re-entry for the whole
    // callback, satisfying the architecture trampoline's non-sleep contract.
    unsafe {
        hal_x86_64::call_on_irq_stack(run_pending_on_irq_stack);
    }
}

impl softirq::HandlerAccounting for SchedHandlerAccounting {
    type Snapshot = u32;

    fn before() -> u32 { preempt::preempt_count() }

    fn after(expected: u32) {
        let actual = preempt::preempt_count();
        if actual == expected { return; }
        #[cfg(feature = "debug-preempt")]
        {
            klog::write_raw(b"[BUG] softirq changed preempt_count: entered=");
            klog::write_hex_u64(expected as u64);
            klog::write_raw(b" exited=");
            klog::write_hex_u64(actual as u64);
            klog::write_raw(b"\n");
        }
        preempt::preempt_count_set(expected);
    }
}

/// Linux `local_bh_disable`: disable softirq processing on THIS CPU by raising
/// its preempt_count softirq field. Pairs with `local_bh_enable`. Cheap; the
/// running task can't migrate while bh-disabled (count blocks resched).
/// # C: O(1)
#[inline]
pub fn local_bh_disable() {
    preempt::preempt_count_add(SOFTIRQ_DISABLE_OFFSET);
}

/// Linux `local_bh_enable`: re-enable softirqs. If this is the outermost
/// disable and work is pending, drain it first (still marked `in_serving` so
/// preemption stays off and nested raises don't recurse), then drop the
/// disable count and take a pending reschedule.
/// # SAFETY: must pair a prior `local_bh_disable`; safe schedule point (not in
/// an IRQ handler, no scheduler-needed lock held).
/// # C: O(1) + drain
pub unsafe fn local_bh_enable() {
    debug_assert!(preempt::softirq_count() >= SOFTIRQ_DISABLE_OFFSET, "local_bh_enable without disable");
    // A hard-IRQ handler may bh-disable to touch a softirq-shared lock (the
    // console sink runs in every context there is). Its matching enable must
    // NOT drain here: a drain from an interrupt handler runs softirq work on
    // the interrupt stack and, worse, reaches the reschedule check below on a
    // stack that cannot be switched away from. The IRQ tail runs the drain
    // once the handler returns, so nothing is lost by skipping it.
    let interrupt = preempt::hardirq_count() != 0;
    if !interrupt && preempt::softirq_count() == SOFTIRQ_DISABLE_OFFSET && softirq::pending() {
        // Drop the disable portion but keep one SOFTIRQ_OFFSET: in_serving =
        // true, preempt still off, while we drain (Linux keeps preempt off
        // across the do_softirq call in __local_bh_enable_ip).
        preempt::preempt_count_sub(SOFTIRQ_DISABLE_OFFSET - SOFTIRQ_OFFSET);
        // Linux `do_softirq_own_stack`: the complete softirq tree belongs to
        // the per-CPU IRQ stack, not to an arbitrary syscall's task stack.
        // SAFETY: bh-accounted; the callback cannot sleep.
        unsafe { do_softirq_own_stack(); }
        preempt::preempt_count_sub(SOFTIRQ_OFFSET);
    } else {
        preempt::preempt_count_sub(SOFTIRQ_DISABLE_OFFSET);
    }
    if interrupt { return; }
    // SAFETY: caller asserted a safe schedule point.
    unsafe { preempt::preempt_check_resched(); }
}

/// Linux `__local_bh_enable`: drop the disable without draining. For a caller
/// that may hold an unrelated lock, or that runs in a context it does not
/// control — the console sink is reachable from anywhere, including from inside
/// another subsystem's critical section — running softirq handlers inline on
/// the way out is the wrong trade. Pending work stays pending and the next IRQ
/// tail or `ksoftirqd` pass takes it.
/// # SAFETY: must pair a prior [`local_bh_disable`].
/// # C: O(1)
#[inline]
pub unsafe fn local_bh_enable_no_drain() {
    debug_assert!(preempt::softirq_count() >= SOFTIRQ_DISABLE_OFFSET, "local_bh_enable without disable");
    preempt::preempt_count_sub(SOFTIRQ_DISABLE_OFFSET);
}

/// Linux `do_softirq`: drain THIS CPU's pending softirqs. No-op if already in a
/// bottom-half/IRQ context (re-entry guard) or nothing is pending. Marks
/// `in_serving_softirq` across the drain so a nested raise/timer can't recurse
/// and `spin_lock_bh` nests correctly.
/// # SAFETY: IRQ-tail or process (ksoftirqd) context; IRQs may be enabled;
/// not holding a lock the softirq handlers also take.
/// # C: O(pending softirq work)
pub unsafe fn do_softirq() {
    if preempt::in_interrupt() { return; }
    if !softirq::pending() { return; }
    preempt::preempt_count_add(SOFTIRQ_OFFSET); // in_serving_softirq = true
    // SAFETY: bh-accounted; the core drains this CPU's mask (restart gate).
    unsafe { softirq::run_pending_accounted::<SchedHandlerAccounting>(); }
    preempt::preempt_count_sub(SOFTIRQ_OFFSET);
}

/// The IRQ-tail drain, split so the bottom-half count is taken while
/// interrupts are still OFF.
///
/// `do_softirq` above takes `SOFTIRQ_OFFSET` itself, which is correct for a
/// caller that already has interrupts enabled. It is NOT correct for the
/// interrupt tail: the dispatcher there enables interrupts and then calls in,
/// so between the two a nested dispatch observes `in_interrupt() == 0`, decides
/// it may drain, and opens its OWN interrupt-enabled window. Every nesting
/// level can do that, on one 16 KiB stack, with nothing bounding the depth —
/// which is how a burst of serial receive interrupts walked the interrupt stack
/// into its guard page.
///
/// The reference takes the count first and enables interrupts after
/// (`irq_exit_rcu` -> `__local_bh_disable_ip(SOFTIRQ_OFFSET)`, then
/// `local_irq_enable()` inside the drain). These three make the dispatcher able
/// to do the same while the `sti`/`cli` stay in arch code.
///
/// Returns false when there is nothing to do; the caller must not enable
/// interrupts or call the other two in that case.
/// # C: O(1)
pub fn softirq_tail_begin() -> bool {
    if preempt::in_interrupt() { return false; }
    if !softirq::pending() { return false; }
    preempt::preempt_count_add(SOFTIRQ_OFFSET);
    true
}

/// Run the drain. Call only between [`softirq_tail_begin`] returning true and
/// [`softirq_tail_end`].
/// # SAFETY: bottom-half count is held by `softirq_tail_begin`; interrupts may be enabled.
/// # C: O(pending softirq work)
pub unsafe fn softirq_tail_run() {
    // SAFETY: bh-accounted by softirq_tail_begin; drains this CPU's mask.
    unsafe { softirq::run_pending_accounted::<SchedHandlerAccounting>(); }
}

/// Release the bottom-half count. Call with interrupts OFF again, so the count
/// is never dropped while a nested dispatch could still observe it.
/// # C: O(1)
pub fn softirq_tail_end() { preempt::preempt_count_sub(SOFTIRQ_OFFSET); }

/// Drain softirqs from ksoftirqd, including process-only slots. # C: O(pending work)
/// # SAFETY: process-context kthread, IRQs enabled, no handler-owned lock held.
pub unsafe fn do_softirq_process() {
    if preempt::in_interrupt() { return; }
    if !softirq::pending() { return; }
    preempt::preempt_count_add(SOFTIRQ_OFFSET);
    // SAFETY: process-context bh-accounted drain.
    unsafe { softirq::run_pending_process_accounted::<SchedHandlerAccounting>(); }
    preempt::preempt_count_sub(SOFTIRQ_OFFSET);
}

/// The `BhGate` `sync` needs to implement `spin_lock_bh`. `sync` sits below
/// `sched` in the dep order and cannot reach `preempt_count`, so the gate is
/// supplied as a generic parameter — the same arrangement as `IrqGate`.
///
/// Call as `lock.lock_bh::<sched::bh::SchedBh>()`; that is the whole of Linux's
/// `spin_lock_bh` for a lock shared with a SOFTIRQ. For a lock shared with a
/// hard-IRQ handler use `lock_irqsave` instead — disabling bottom halves does
/// not exclude an interrupt.
pub struct SchedBh;

impl sync::BhGate for SchedBh {
    /// # C: O(1)
    unsafe fn disable() { local_bh_disable(); }
    /// # SAFETY: `lock_bh`'s guard releases the lock before calling this, so the
    /// inline drain may take that lock; caller is at a legal schedule point.
    /// # C: O(1) + drain
    unsafe fn enable() {
        // SAFETY: pairs the disable() above via LockBhGuard::drop, which has
        // already released the lock — so a drain here cannot self-deadlock.
        unsafe { local_bh_enable(); }
    }
}

/// RAII `spin_lock_bh` building block (Linux `local_bh_disable` + lock). Hold
/// across a `Spinlock` guard to exclude this CPU's softirqs; drop re-enables
/// bottom halves (draining any that arrived) after the lock is released.
///
/// Usage: `let _bh = BhGuard::new(); let g = lock.lock(); /* ... */` — drop
/// order (g then _bh) gives Linux `spin_unlock_bh` semantics.
pub struct BhGuard {
    _private: (),
}

impl BhGuard {
    /// `local_bh_disable`. # C: O(1)
    pub fn new() -> Self {
        local_bh_disable();
        Self { _private: () }
    }
}

impl Default for BhGuard {
    fn default() -> Self { Self::new() }
}

impl Drop for BhGuard {
    fn drop(&mut self) {
        // SAFETY: pairs the new()'s local_bh_disable; drop sites are ordinary
        // kernel context (lock already released by the inner guard) — a safe
        // schedule point per the spin_lock_bh contract.
        unsafe { local_bh_enable(); }
    }
}

/// [`BhGuard`] for a caller that cannot afford the inline drain — see
/// [`local_bh_enable_no_drain`].
pub struct BhGuardNoDrain {
    _private: (),
}

impl BhGuardNoDrain {
    /// `local_bh_disable`. # C: O(1)
    pub fn new() -> Self {
        local_bh_disable();
        Self { _private: () }
    }
}

impl Default for BhGuardNoDrain {
    fn default() -> Self { Self::new() }
}

impl Drop for BhGuardNoDrain {
    fn drop(&mut self) {
        // SAFETY: pairs this guard's own local_bh_disable; no drain, so no
        // handler runs here and no lock the caller holds can be re-entered.
        unsafe { local_bh_enable_no_drain(); }
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use super::*;
    use crate::preempt;
    use std::sync::{Barrier, Mutex, MutexGuard};

    static SOFTIRQ_STATE: Mutex<()> = Mutex::new(());

    fn own_softirq_state() -> MutexGuard<'static, ()> {
        match SOFTIRQ_STATE.lock() {
            Ok(guard) => guard,
            Err(poisoned) => { SOFTIRQ_STATE.clear_poison(); poisoned.into_inner() }
        }
    }

    #[test]
    fn bh_disable_enable_balances_and_marks_in_interrupt() {
        preempt::_test_reset();
        assert_eq!(preempt::preempt_count(), 0);
        local_bh_disable();
        assert_eq!(preempt::softirq_count(), preempt::SOFTIRQ_DISABLE_OFFSET);
        // bh-disabled counts as in_interrupt (Linux) and blocks resched.
        assert!(preempt::in_interrupt());
        assert!(!preempt::in_serving_softirq()); // even field = disabled, not serving
        // SAFETY: pairs the disable above; host test, schedule hook null.
        unsafe { local_bh_enable(); }
        assert_eq!(preempt::preempt_count(), 0);
        assert!(!preempt::in_interrupt());
    }

    #[test]
    fn do_softirq_bails_when_in_interrupt() {
        preempt::_test_reset();
        // Simulate "already serving a softirq" on this CPU.
        preempt::preempt_count_add(preempt::SOFTIRQ_OFFSET);
        assert!(preempt::in_serving_softirq());
        // do_softirq must see in_interrupt and return without touching the count.
        // SAFETY: host test; re-entry guard path, no drain.
        unsafe { do_softirq(); }
        assert_eq!(preempt::softirq_count(), preempt::SOFTIRQ_OFFSET);
        preempt::preempt_count_sub(preempt::SOFTIRQ_OFFSET);
        assert_eq!(preempt::preempt_count(), 0);
    }

    /// A hard-IRQ handler that bh-disables to touch a softirq-shared lock must
    /// not drain softirq work when it re-enables: the drain belongs to the IRQ
    /// tail, which runs once the handler returns.
    #[test]
    fn enable_from_hard_irq_defers_the_drain_to_the_irq_tail() {
        static RAN: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
        fn handler() { RAN.fetch_add(1, core::sync::atomic::Ordering::Relaxed); }
        let _state = own_softirq_state();
        preempt::_test_reset();
        RAN.store(0, core::sync::atomic::Ordering::Relaxed);
        softirq::set_handler(softirq::Slot::Tasklet, handler);
        preempt::preempt_count_add(preempt::HARDIRQ_OFFSET);
        local_bh_disable();
        softirq::raise(softirq::Slot::Tasklet);
        // SAFETY: pairs the disable above; host test in simulated IRQ context.
        unsafe { local_bh_enable(); }
        assert_eq!(RAN.load(core::sync::atomic::Ordering::Relaxed), 0);
        assert!(softirq::pending(), "work stays pending for the IRQ tail");
        preempt::preempt_count_sub(preempt::HARDIRQ_OFFSET);
        // Out of interrupt context the same enable does drain it.
        local_bh_disable();
        // SAFETY: pairs the disable above; process context, no lock held.
        unsafe { local_bh_enable(); }
        assert_eq!(RAN.load(core::sync::atomic::Ordering::Relaxed), 1);
        softirq::clear_handler(softirq::Slot::Tasklet);
        preempt::_test_reset();
    }

    fn corrupt_preempt_count() { preempt::preempt_count_set(0); }

    #[test]
    fn handler_count_violation_is_repaired_before_outer_softirq_exit() {
        let _state = own_softirq_state();
        preempt::_test_reset();
        softirq::set_handler(softirq::Slot::Tasklet, corrupt_preempt_count);
        softirq::raise(softirq::Slot::Tasklet);
        // SAFETY: hosted process-context drain; handler deliberately models a
        // schedule-bug recovery that returned with its softirq count cleared.
        unsafe { do_softirq_process(); }
        assert_eq!(preempt::preempt_count(), 0);
        softirq::clear_handler(softirq::Slot::Tasklet);
        preempt::_test_reset();
    }

    #[test]
    fn bh_guard_raii_balances() {
        preempt::_test_reset();
        {
            let _bh = BhGuard::new();
            assert_eq!(preempt::softirq_count(), preempt::SOFTIRQ_DISABLE_OFFSET);
        }
        assert_eq!(preempt::preempt_count(), 0);
    }

    #[test]
    fn test_reset_does_not_erase_another_cpu_bh_nesting() {
        let disabled = Arc::new(Barrier::new(2));
        let reset = Arc::new(Barrier::new(2));
        let owner = {
            let disabled = disabled.clone();
            let reset = reset.clone();
            std::thread::spawn(move || {
                preempt::_test_reset();
                local_bh_disable();
                disabled.wait();
                reset.wait();
                assert_eq!(preempt::softirq_count(), preempt::SOFTIRQ_DISABLE_OFFSET);
                // SAFETY: pairs this thread's local_bh_disable; host hook null.
                unsafe { local_bh_enable(); }
            })
        };
        let resetter = std::thread::spawn(move || {
            disabled.wait();
            preempt::_test_reset();
            reset.wait();
        });
        owner.join().unwrap();
        resetter.join().unwrap();
    }
}
