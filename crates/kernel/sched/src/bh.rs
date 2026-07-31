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
        // SAFETY: bh-accounted; drains this CPU's mask with the restart gate.
        unsafe { softirq::run_pending(); }
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
    unsafe { softirq::run_pending(); }
    preempt::preempt_count_sub(SOFTIRQ_OFFSET);
}

/// Drain softirqs from ksoftirqd, including process-only slots. # C: O(pending work)
/// # SAFETY: process-context kthread, IRQs enabled, no handler-owned lock held.
pub unsafe fn do_softirq_process() {
    if preempt::in_interrupt() { return; }
    if !softirq::pending() { return; }
    preempt::preempt_count_add(SOFTIRQ_OFFSET);
    // SAFETY: process-context bh-accounted drain.
    unsafe { softirq::run_pending_process(); }
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
    use std::sync::Barrier;

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
