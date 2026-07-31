// Context contract for `VT_STATE`: a process-context holder must exclude this
// processor's bottom halves, because the `FbconFlush` softirq takes the same
// lock.
//
// The failure these pin down is a same-processor self-deadlock, not a cross-CPU
// race: an interrupt arriving inside a process-context critical section runs
// the softirq drain on its way out, and the drain's `repaint` waits for a lock
// the interrupted context still holds. It only reaches process context that
// runs with interrupts unmasked — a kernel thread writing to the console — so a
// purely userspace workload never showed it.

use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};

use super::shared::{lock_vt, try_lock_vt, VT_STATE};

/// Serialises these tests against each other and against the rest of the crate:
/// `VT_STATE`, the softirq tables and the preempt count are all process-global.
static SERIAL: sync::Spinlock<(), sync::Devices> = sync::Spinlock::new(());

/// Times the stand-in flush handler ran.
static RAN: AtomicU32 = AtomicU32::new(0);
/// Whether the handler found `VT_STATE` already taken — the state in which the
/// real handler's blocking acquisition never returns.
static WOULD_BLOCK: AtomicBool = AtomicBool::new(false);

/// Stands in for `flush_softirq`. The real one acquires `VT_STATE` and would
/// spin here forever, so this records the observation instead of reproducing
/// the hang.
fn probe_handler() {
    RAN.fetch_add(1, Ordering::Relaxed);
    match VT_STATE.try_lock() {
        Some(_) => {}
        None => WOULD_BLOCK.store(true, Ordering::Relaxed),
    }
}

fn arm() {
    RAN.store(0, Ordering::Relaxed);
    WOULD_BLOCK.store(false, Ordering::Relaxed);
    softirq::set_handler(softirq::Slot::FbconFlush, probe_handler);
    softirq::raise(softirq::Slot::FbconFlush);
}

fn disarm() {
    softirq::clear_handler(softirq::Slot::FbconFlush);
}

/// The shape of the wedge: with `VT_STATE` held the way process context used to
/// hold it — no bottom-half exclusion — the drain runs the flush handler and it
/// finds the lock already taken. In the kernel that is the point of no return.
#[test]
fn a_plain_acquisition_lets_the_flush_softirq_re_enter() {
    let _serial = SERIAL.lock();
    arm();
    {
        let _held = VT_STATE.lock();
        // SAFETY: hosted; process context with no scheduler installed.
        unsafe { sched::bh::do_softirq(); }
        assert_eq!(RAN.load(Ordering::Relaxed), 1, "drain ran the handler");
        assert!(WOULD_BLOCK.load(Ordering::Relaxed), "handler reached a held lock");
    }
    disarm();
}

/// The contract: a process-context acquisition disables bottom halves, so the
/// drain is a no-op for as long as the lock is held.
#[test]
fn lock_vt_excludes_the_flush_softirq() {
    let _serial = SERIAL.lock();
    arm();
    {
        let _held = lock_vt();
        assert!(sched::preempt::in_interrupt(), "bottom halves disabled while held");
        // SAFETY: hosted; the bail is what is under test.
        unsafe { sched::bh::do_softirq(); }
        assert_eq!(RAN.load(Ordering::Relaxed), 0, "drain refused while held");
        assert!(!WOULD_BLOCK.load(Ordering::Relaxed));
    }
    disarm();
}

/// The non-blocking acquisition (the klog sink's) carries the same exclusion —
/// it is the one the wedged boot was inside.
#[test]
fn try_lock_vt_excludes_the_flush_softirq() {
    let _serial = SERIAL.lock();
    arm();
    {
        let _held = try_lock_vt().expect("uncontended");
        assert!(sched::preempt::in_interrupt(), "bottom halves disabled while held");
        // SAFETY: hosted; the bail is what is under test.
        unsafe { sched::bh::do_softirq(); }
        assert_eq!(RAN.load(Ordering::Relaxed), 0, "drain refused while held");
    }
    disarm();
}

/// Excluding the softirq defers it, never drops it: releasing the guard runs
/// the flush that arrived meanwhile, and by then the lock is free.
#[test]
fn releasing_the_guard_runs_the_deferred_flush() {
    let _serial = SERIAL.lock();
    arm();
    drop(lock_vt());
    assert_eq!(RAN.load(Ordering::Relaxed), 1, "deferred flush ran on release");
    assert!(!WOULD_BLOCK.load(Ordering::Relaxed), "lock free by the time it ran");
    disarm();
}

/// A hard-IRQ handler may take the same lock (the console sink runs in every
/// context there is), so the bottom-half enable it pairs with must not drain
/// softirq work onto the interrupt stack.
#[test]
fn bh_enable_does_not_drain_from_a_hard_irq() {
    let _serial = SERIAL.lock();
    arm();
    sched::preempt::preempt_count_add(sched::preempt::HARDIRQ_OFFSET);
    drop(try_lock_vt().expect("uncontended"));
    assert_eq!(RAN.load(Ordering::Relaxed), 0, "no drain from interrupt context");
    sched::preempt::preempt_count_sub(sched::preempt::HARDIRQ_OFFSET);
    disarm();
}
