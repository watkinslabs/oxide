use super::*;
use crate::{Buddy, Spinlock};
#[cfg(feature = "debug-preempt")]
use crate::LockClass;

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
#[cfg(feature = "debug-preempt")]
use crate::test_serial::set_cpu;

static COUNTING: PreemptOps = PreemptOps {
    disable: up,
    enable: down,
};

fn with_ops<R>(f: impl FnOnce() -> R) -> R {
    let _serial = crate::test_serial::gate();
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
        let lk: Spinlock<u32, crate::TaskList> = Spinlock::new(0);
        core::mem::forget(lk.lock());
        assert_eq!(depth(), 1);
        #[cfg(feature = "debug-preempt")]
        assert_eq!(held_rank(), crate::TaskList::rank());
        // SAFETY: exactly one forgotten guard holds this lock.
        unsafe { lk.raw_unlock(); }
        assert_eq!(depth(), 0);
        #[cfg(feature = "debug-preempt")]
        assert_eq!(held_rank(), 0);
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

#[cfg(feature = "debug-preempt")]
#[test]
fn held_rank_is_per_cpu_and_restores_the_outer_lock() {
    with_ops(|| {
        let me = crate::test_serial::pinned(0);
        set_cpu(me);
        let outer: Spinlock<u32, crate::TaskList> = Spinlock::new(0);
        let inner: Spinlock<u32, crate::TaskWake> = Spinlock::new(0);
        let _outer = outer.lock();
        assert_eq!(held_rank(), crate::TaskList::rank());
        {
            let _inner = inner.lock();
            assert_eq!(held_rank(), crate::TaskWake::rank());
        }
        assert_eq!(held_rank(), crate::TaskList::rank());

        let peer = std::thread::spawn(|| {
            set_cpu(crate::test_serial::pinned(1));
            let other: Spinlock<u32, crate::Tty> = Spinlock::new(0);
            let _other = other.lock();
            assert_eq!(held_rank(), crate::Tty::rank());
        });
        peer.join().unwrap();
        assert_eq!(held_rank(), crate::TaskList::rank(),
            "a peer CPU must not overwrite this CPU's diagnostic stack");
    });
}

// A cross-CPU stall report names a WEDGED CPU, and that CPU cannot run its own
// reporter. The frames it is holding are the only readable evidence of where
// it stopped, so a peer must be able to read them by CPU index while they are
// still held.
#[cfg(feature = "debug-preempt")]
#[test]
fn a_wedged_cpus_held_frames_are_readable_by_index_from_a_peer() {
    use std::sync::mpsc;
    with_ops(|| {
        let me = crate::test_serial::pinned(2);
        let wedged_cpu = crate::test_serial::pinned(3);
        set_cpu(me);
        let (held_tx, held_rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel();
        let wedged = std::thread::spawn(move || {
            set_cpu(wedged_cpu);
            let lk: Spinlock<u32, crate::Tty> = Spinlock::new(0);
            let g = lk.lock();
            held_tx.send(()).unwrap();
            go_rx.recv().unwrap();
            drop(g);
        });
        held_rx.recv().unwrap();
        assert_eq!(held_depth_on(wedged_cpu), 1, "the wedged CPU's frame must be visible from here");
        let (rank, site) = held_frame_on(wedged_cpu, 0).expect("frame 0 of the wedged CPU");
        assert_eq!(rank, crate::Tty::rank());
        let site = site.expect("the acquisition site is recorded");
        assert!(site.file().ends_with("tests.rs"),
            "the site names the acquiring file, got {}", site.file());
        assert!(held_frame_on(wedged_cpu, 1).is_none(), "no frame beyond the tracked depth");
        assert_eq!(held_depth_on(me), 0, "reading a peer must not report our own frames");
        go_tx.send(()).unwrap();
        wedged.join().unwrap();
        assert_eq!(held_depth_on(wedged_cpu), 0, "the release pops the wedged CPU's frame");
    });
}

// A lock taken BEFORE the preempt gate is installed still has a CPU, and its
// release pops that CPU's stack. Pushing it onto CPU 0 instead made one trace
// grow without bound and another underflow, on the boot path where the gate is
// not yet installed.
#[cfg(feature = "debug-preempt")]
#[test]
fn an_acquisition_before_the_gate_is_installed_traces_on_its_own_cpu() {
    let _serial = crate::test_serial::gate();
    OPS.store(core::ptr::null_mut(), Ordering::Release);
    let me = crate::test_serial::pinned(4);
    set_cpu(me);
    let before = held_depth_on(me);
    let lk: Spinlock<u32, crate::Tty> = Spinlock::new(0);
    {
        let _g = lk.lock();
        assert_eq!(held_depth_on(me), before + 1,
            "an uninstalled-gate acquisition must trace on the CPU that took it");
    }
    assert_eq!(held_depth_on(me), before, "and its release must pop the same CPU");
}

// An out-of-range CPU index must clamp rather than index past the array: the
// stall reporter is handed a raw CPU number from a diagnostic path.
#[cfg(feature = "debug-preempt")]
#[test]
fn an_out_of_range_cpu_index_clamps_instead_of_faulting() {
    with_ops(|| {
        assert_eq!(held_depth_on(usize::MAX), held_depth_on(crate::MAX_CPUS - 1));
        assert!(held_frame_on(usize::MAX, 0).is_none()
            || held_frame_on(crate::MAX_CPUS - 1, 0).is_some());
    });
}
