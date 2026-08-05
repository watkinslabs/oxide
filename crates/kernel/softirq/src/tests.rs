use super::*;
use core::sync::atomic::AtomicU32;
use std::sync::{Mutex, MutexGuard};

// `PENDING`, `PROCESS_PENDING` and `HANDLERS` are the processor's ONE
// softirq state, and a hosted test binary models exactly one processor.
// Every test here mutates all three, so each must own that state for its
// whole body: two tests running in parallel otherwise clear each other's
// pending bits and overwrite each other's handlers, and whichever loses
// reports a handler that "never ran" or a bit that "stayed set".
static SOFTIRQ_STATE: Mutex<()> = Mutex::new(());

fn own_softirq_state() -> MutexGuard<'static, ()> {
    let guard = match SOFTIRQ_STATE.lock() {
        Ok(guard) => guard,
        Err(poisoned) => { SOFTIRQ_STATE.clear_poison(); poisoned.into_inner() }
    };
    PENDING[0].store(0, Ordering::Relaxed);
    PROCESS_PENDING.store(0, Ordering::Relaxed);
    guard
}

static T_HITS: AtomicU32 = AtomicU32::new(0);
fn t_handler() { T_HITS.fetch_add(1, Ordering::Relaxed); }

static REARM_HITS: AtomicU32 = AtomicU32::new(0);
fn rearming_handler() {
    REARM_HITS.fetch_add(1, Ordering::Relaxed);
    raise(Slot::NetRx);
}
fn noop_handler() {}
static PROCESS_HITS: AtomicU32 = AtomicU32::new(0);
fn process_handler() { PROCESS_HITS.fetch_add(1, Ordering::Relaxed); }

#[test]
fn raise_then_run_invokes_handler() {
    let _state = own_softirq_state();
    T_HITS.store(0, Ordering::Relaxed);
    set_handler(Slot::FbconFlush, t_handler);
    raise(Slot::FbconFlush);
    assert!(pending());
    // SAFETY: hosted unit test; no IRQs to coordinate with; sole caller of run_pending in this thread.
    unsafe { run_pending(); }
    assert!(!pending());
    assert_eq!(T_HITS.load(Ordering::Relaxed), 1);
}

#[test]
fn process_only_slot_waits_for_process_drain() {
    let _state = own_softirq_state();
    PROCESS_HITS.store(0, Ordering::Relaxed);
    set_handler(Slot::NetNsReap, process_handler);
    raise_process(Slot::NetNsReap);
    // SAFETY: hosted test models an IRQ-tail accounting bracket.
    unsafe { run_pending(); }
    assert_eq!(PROCESS_HITS.load(Ordering::Relaxed), 0);
    assert!(pending());
    // SAFETY: hosted test models the ksoftirqd accounting bracket.
    unsafe { run_pending_process(); }
    assert_eq!(PROCESS_HITS.load(Ordering::Relaxed), 1);
    assert!(!pending());
}

#[test]
fn run_pending_drains_until_empty() {
    let _state = own_softirq_state();
    T_HITS.store(0, Ordering::Relaxed);
    set_handler(Slot::FbconFlush, t_handler);
    raise(Slot::FbconFlush);
    raise(Slot::FbconFlush);
    // SAFETY: hosted unit test; no IRQs to coordinate with; sole caller of run_pending in this thread.
    unsafe { run_pending(); }
    assert_eq!(T_HITS.load(Ordering::Relaxed), 1);
}

#[test]
fn unset_slot_no_handler_no_call() {
    let _state = own_softirq_state();
    HANDLERS[Slot::InputDrain as usize].store(core::ptr::null_mut(), Ordering::Relaxed);
    raise(Slot::InputDrain);
    // SAFETY: hosted unit test; no IRQs to coordinate with; sole caller of run_pending in this thread.
    unsafe { run_pending(); }
    assert!(!pending());
}

#[test]
fn clear_handler_removes_handler_and_pending_bit() {
    let _state = own_softirq_state();
    T_HITS.store(0, Ordering::Relaxed);
    set_handler(Slot::VsockRx, t_handler);
    raise(Slot::VsockRx);
    assert!(pending());
    let old = clear_handler(Slot::VsockRx);
    assert!(!old.is_null());
    assert!(!pending());
    // SAFETY: hosted unit test; no IRQs to coordinate with; sole caller of run_pending in this thread.
    unsafe { run_pending(); }
    assert_eq!(T_HITS.load(Ordering::Relaxed), 0);
}

#[test]
fn self_rearming_handler_is_bounded() {
    let _state = own_softirq_state();
    REARM_HITS.store(0, Ordering::Relaxed);
    set_handler(Slot::NetRx, rearming_handler);
    raise(Slot::NetRx);
    // SAFETY: hosted unit test; no IRQs to coordinate with; sole caller of run_pending in this thread.
    unsafe { run_pending(); }
    assert_eq!(REARM_HITS.load(Ordering::Relaxed), MAX_SOFTIRQ_RESTART);
    assert!(pending());
    set_handler(Slot::NetRx, noop_handler);
}
