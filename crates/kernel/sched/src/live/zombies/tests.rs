// Hosted regression coverage for the WAITERS park/wake path (`wait4`'s
// blocking parent registry). Both properties pinned here close the same bug
// class this tree has hit repeatedly elsewhere (`WaitList::park_with_deadline`
// dedup, `try_to_wake_up`'s claim-then-place CAS): a generic signal wake can
// resume a parked task WITHOUT clearing whatever subsystem-specific list
// parked it, leaving a stale entry that a later publisher can misuse.
//
// Trap this suite avoids (per the harness note that motivated it): a naive
// "park, wake, assert woken" test only proves a token got set — std's
// park/unpark semantics (and this codebase's Sleeping/Runnable CAS) make that
// trivially true regardless of ordering. Both tests below instead assert a
// STRUCTURAL invariant (WAITERS entry count; on_rq state) that the pre-fix
// code provably violated — see the inline "pre-fix" notes.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::*;
use crate::live::runqueue::{self, Runqueue};
use crate::task::SchedClass;

/// `runqueue::GLOBALS`/`WAITERS` are process-wide statics keyed on the hosted
/// "cpu 0" (`this_cpu()` is unconditionally 0 off-target). Serialize this
/// module's tests so parallel `cargo test` threads can't collide installing/
/// tearing down the same slot.
fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Install a fresh single-CPU runqueue and publish `cur` as its `current`.
/// # SAFETY: test-only; serialized by `test_lock`, torn down by `uninstall`.
fn install(cur: &Arc<Task>) {
    let idle = Arc::new(Task::new(0xFFFF_0000, "idle", SchedClass::Idle));
    unsafe { runqueue::install_global(Runqueue::new(0, idle)); }
    let rq = runqueue::global().expect("just installed");
    let _ = unsafe { rq.swap_current(Arc::clone(cur)) };
}

/// Pair `install`'s runqueue install and reset WAITERS for the next test.
/// # SAFETY: test-only; matches a prior `install` call under `test_lock`.
fn uninstall() {
    unsafe { runqueue::uninstall_global(); }
    WAITERS.lock().clear();
}

/// Pop `tid` off whichever class list holds it and clear `on_rq` — models
/// `pick_next_task` having handed it the CPU (it is now genuinely executing:
/// `on_rq=false`, `on_cpu=true`).
fn pop_to_running(parent: &Arc<Task>) {
    let rq = runqueue::global().expect("installed");
    {
        let mut inner = rq.inner.lock();
        let _ = inner.remove(parent.tid);
        rq.nr_running.store(inner.nr_running(), Ordering::Release);
    }
    parent.on_rq.store(false, Ordering::Release);
    parent.on_cpu.store(true, Ordering::Release);
}

#[test]
fn park_for_wait4_dedups_a_stale_entry_left_by_an_unrelated_wake() {
    let _g = test_lock();
    WAITERS.lock().clear();
    let parent = Arc::new(Task::new(9101, "parent", SchedClass::Normal { weight: 1024 }));
    install(&parent);

    // First park: one WAITERS entry, Sleeping.
    unsafe { park_for_wait4(); }
    assert_eq!(WAITERS.lock().iter().filter(|t| t.tid == parent.tid).count(), 1);
    assert_eq!(parent.state(), TaskState::Sleeping);

    // An unrelated wake (a signal, `wake_if_sleeping`, `vfork_done`, ...)
    // resumes the parent through the GENERIC scheduler wake path, which has
    // no notion of WAITERS and therefore cannot pop this entry.
    assert!(unsafe { crate::live::try_to_wake_up(Arc::clone(&parent)) });
    assert_eq!(parent.state(), TaskState::Runnable);
    assert_eq!(WAITERS.lock().iter().filter(|t| t.tid == parent.tid).count(), 1,
        "the generic wake must not have touched the stale WAITERS entry");

    // Parent's wait4 loop finds nothing to reap (unrelated wake) and re-parks.
    pop_to_running(&parent);
    unsafe { park_for_wait4(); }

    // Pre-fix `park_for_wait4` unconditionally pushed, so this would be 2 —
    // a permanently-duplicated WAITERS registration for one live task.
    let count = WAITERS.lock().iter().filter(|t| t.tid == parent.tid).count();
    assert_eq!(count, 1, "park_for_wait4 must dedup a stale entry for the same tid");

    uninstall();
}

#[test]
fn wake_wait4_parent_drops_a_stale_entry_instead_of_re_placing_a_running_task() {
    let _g = test_lock();
    WAITERS.lock().clear();
    let parent = Arc::new(Task::new(9102, "parent", SchedClass::Normal { weight: 1024 }));
    install(&parent);

    unsafe { park_for_wait4(); }
    assert_eq!(parent.state(), TaskState::Sleeping);

    // Resume through the generic wake path without popping WAITERS, then
    // model the scheduler having picked it: on_rq=false, on_cpu=true, i.e.
    // the parent is ACTIVELY RUNNING right now with a stale WAITERS entry
    // still pointing at it.
    assert!(unsafe { crate::live::try_to_wake_up(Arc::clone(&parent)) });
    assert!(parent.on_rq.load(Ordering::Acquire), "try_to_wake_up enqueues onto the runqueue");
    pop_to_running(&parent);

    // A child of this parent exits: enqueue_zombie's wake step calls
    // wake_wait4_parent, which still finds the stale WAITERS entry.
    wake_wait4_parent(parent.tid);

    // Pre-fix: `t.set_state(Runnable)` (no-op — already Runnable) followed by
    // an UNCONDITIONAL `inner.enqueue(t)`. `on_rq` is false (the task is
    // executing, not queued), so `RunqueueInner::enqueue`'s on_rq guard would
    // accept it — landing a task that is simultaneously `on_cpu=true` into
    // the ready tree. Post-fix, `claim_wake` requires the observed state to
    // be exactly `Sleeping`; it is `Runnable`, so the stale entry is dropped
    // and `on_rq` must stay false.
    assert!(!parent.on_rq.load(Ordering::Acquire),
        "a stale WAITERS entry for an already-running task must not be re-enqueued");
    assert!(WAITERS.lock().iter().all(|t| t.tid != parent.tid),
        "wake_wait4_parent always removes a matching entry, claimed or not");

    uninstall();
}
