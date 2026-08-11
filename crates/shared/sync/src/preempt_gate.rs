// The preemption gate every spinning lock in this crate takes, and the reason
// it exists.
//
// A spinning lock is only correct while its owner keeps running. The reference
// makes that structural rather than hopeful: `spin_lock` is
// `preempt_disable()` + the acquire, and `spin_unlock` is the release +
// `preempt_enable()`, so an owner CANNOT be descheduled inside its critical
// section. On a uniprocessor build the acquire itself compiles away entirely
// and the preempt-disable IS the lock.
//
// Without it, an owner that reaches ANY voluntary reschedule point inside the
// section — a `local_bh_enable` at the end of a nested bottom-half section, a
// `preempt_enable` returning to zero with a pending request — gives up the CPU
// still holding the lock. Every later acquirer then spins for a lock whose
// owner is not running. With a second CPU a peer picks the owner up and the
// window closes in microseconds, which is why the shape survives an SMP boot;
// with one CPU nothing can run the owner, and if any spinner in the resulting
// chain masks interrupts the machine stops taking ticks altogether.
//
// The count itself belongs to the scheduler, which sits ABOVE this crate in
// the dependency order, so the gate is installed as a pair of function
// pointers — the same shape `spin_relax`, the RCU CPU hooks and the lockdep
// context hook already use. Uninstalled (hosted tests, early boot before the
// scheduler exists) it is inert, and preemption cannot happen there anyway.
//
// PAIRING: `acquire` returns the release half it just used, and every guard
// carries that value to its `Drop`. A lock taken before the ops are installed
// therefore releases with the same (absent) ops it acquired with, so an
// installation that lands mid-critical-section can never produce an unmatched
// decrement.

use core::sync::atomic::{AtomicPtr, Ordering};

/// The scheduler's preempt-count pair, as this crate's locks use it.
/// `disable` must raise the count by exactly one and `enable` must lower it by
/// exactly one WITHOUT taking a reschedule — a spin lock release is not a
/// schedule point in this kernel, and the pending request is taken at the next
/// natural one (return-to-user, `local_bh_enable`, `preempt_enable`).
#[derive(Clone, Copy)]
pub struct PreemptOps {
    /// Linux `preempt_disable`.
    pub disable: fn(),
    /// Linux `preempt_enable_no_resched`.
    pub enable: fn(),
}

static OPS: AtomicPtr<PreemptOps> = AtomicPtr::new(core::ptr::null_mut());

/// Rank of the innermost lock class this CPU currently holds, or 0 for none.
/// A `[BUG] scheduling while atomic` report is otherwise mute about WHICH lock
/// the owner is about to carry off-CPU — it names the schedule site, which is
/// the victim, not the cause. Debug-only; a single slot is exact at the depth
/// that matters (one held lock) and the preempt count states the depth.
#[cfg(feature = "debug-preempt")]
static HELD_RANK: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(0);

/// The innermost held lock class rank, 0 when none. # C: O(1)
#[cfg(feature = "debug-preempt")]
pub fn held_rank() -> u16 { HELD_RANK.load(Ordering::Relaxed) }

/// Install the preempt gate. Boot path, once, as soon as the preempt count is
/// usable and before the first reschedule can be taken.
/// # C: O(1)
pub fn set_preempt_ops(ops: &'static PreemptOps) {
    OPS.store(ops as *const PreemptOps as *mut PreemptOps, Ordering::Release);
}

/// Enter a spinning-lock critical section: raise the preempt count if a gate is
/// installed, and hand back the release half to run on the way out.
/// # C: O(1)
#[inline]
pub(crate) fn acquire(rank: u16) -> Option<fn()> {
    #[cfg(feature = "debug-preempt")]
    HELD_RANK.store(rank, Ordering::Relaxed);
    #[cfg(not(feature = "debug-preempt"))]
    let _ = rank;
    let p = OPS.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: OPS is only ever written by set_preempt_ops from a &'static
    // PreemptOps, so a non-null value is a live 'static pointer to a Copy
    // struct of two fn pointers.
    let ops = unsafe { *p };
    (ops.disable)();
    Some(ops.enable)
}

/// Leave a spinning-lock critical section with the release half `acquire`
/// returned. Called after the lock word is released, so a reschedule taken at
/// the next natural point never finds this lock held.
/// # C: O(1)
#[inline]
pub(crate) fn release(enable: Option<fn()>) {
    #[cfg(feature = "debug-preempt")]
    HELD_RANK.store(0, Ordering::Relaxed);
    if let Some(f) = enable { f(); }
}

/// The installed release half, for the ONE release that cannot carry its own:
/// `Spinlock::raw_unlock`, where the acquiring task forgot its guard and a
/// different task performs the release (the runqueue lock across a context
/// switch). Sound because the ops are installed once, during boot, long before
/// the first switch.
/// # C: O(1)
#[inline]
pub(crate) fn installed_release() -> Option<fn()> {
    let p = OPS.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: same contract as `acquire` — non-null implies a live 'static
    // PreemptOps written by set_preempt_ops.
    Some(unsafe { *p }.enable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Buddy, Spinlock};

    // Per-THREAD depth: `OPS` is global, so while these ops are installed every
    // sibling test's lock traffic runs them too. A process-wide counter reads
    // their acquisitions as this test's.
    std::thread_local! {
        static DEPTH: core::cell::Cell<i64> = const { core::cell::Cell::new(0) };
        static MIN_DEPTH: core::cell::Cell<i64> = const { core::cell::Cell::new(0) };
    }
    fn up() { DEPTH.with(|d| d.set(d.get() + 1)); }
    fn down() {
        DEPTH.with(|d| {
            let next = d.get() - 1;
            d.set(next);
            MIN_DEPTH.with(|m| if next < m.get() { m.set(next) });
        });
    }
    fn depth() -> i64 { DEPTH.with(core::cell::Cell::get) }
    static COUNTING: PreemptOps = PreemptOps { disable: up, enable: down };

    fn with_ops<R>(f: impl FnOnce() -> R) -> R {
        DEPTH.with(|d| d.set(0));
        MIN_DEPTH.with(|m| m.set(0));
        set_preempt_ops(&COUNTING);
        let r = f();
        OPS.store(core::ptr::null_mut(), Ordering::Release);
        r
    }

    #[test]
    fn a_held_spinlock_keeps_preemption_disabled_for_the_whole_section() {
        with_ops(|| {
            let lk: Spinlock<u32, Buddy> = Spinlock::new(0);
            assert_eq!(depth(), 0);
            {
                let mut g = lk.lock();
                assert_eq!(depth(), 1, "spin_lock must disable preemption");
                *g = 5;
                assert_eq!(depth(), 1);
            }
            assert_eq!(depth(), 0, "spin_unlock must re-enable preemption");
            assert_eq!(MIN_DEPTH.with(core::cell::Cell::get), 0,
                "the release ran before its matching disable");
        });
    }

    #[test]
    fn try_lock_gates_preemption_only_when_it_succeeds() {
        with_ops(|| {
            let lk: Spinlock<u32, Buddy> = Spinlock::new(0);
            let held = lk.lock();
            assert_eq!(depth(), 1);
            assert!(lk.try_lock().is_none());
            assert_eq!(depth(), 1, "a failed try_lock must not leave preemption off");
            drop(held);
            let got = lk.try_lock().expect("free lock");
            assert_eq!(depth(), 1);
            drop(got);
            assert_eq!(depth(), 0);
        });
    }

    #[test]
    fn a_forgotten_guard_released_by_raw_unlock_still_balances() {
        // The runqueue lock's cross-task handoff: acquire, forget the guard,
        // and release from `raw_unlock`. The count must come back to zero, or
        // every context switch leaks one preempt level and the CPU stops
        // rescheduling for good.
        with_ops(|| {
            let lk: Spinlock<u32, Buddy> = Spinlock::new(0);
            core::mem::forget(lk.lock());
            assert_eq!(depth(), 1);
            // SAFETY: exactly one forgotten guard holds this lock.
            unsafe { lk.raw_unlock(); }
            assert_eq!(depth(), 0);
            assert!(lk.try_lock().is_some());
        });
    }

    #[test]
    fn an_uninstalled_gate_is_inert() {
        OPS.store(core::ptr::null_mut(), Ordering::Release);
        DEPTH.with(|d| d.set(0));
        let lk: Spinlock<u32, Buddy> = Spinlock::new(0);
        drop(lk.lock());
        assert_eq!(depth(), 0);
    }
}
