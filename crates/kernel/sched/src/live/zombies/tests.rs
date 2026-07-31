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
        rq.publish_nr_running(inner.nr_running());
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

/// The SMP hazard `claim_wake` alone does not cover: a parent that parked in
/// `wait4` and called `schedule()` is genuinely `Sleeping` — so the claim
/// legitimately succeeds — yet it is still `on_cpu` until its CPU's incoming
/// task runs `finish_task_switch`. Placement must go to that CPU's wake-list
/// (Linux `ttwu_queue_wakelist`), never into a ready tree, or `schedule()`
/// picks a task another CPU still owns.
#[test]
fn wake_wait4_parent_defers_a_parent_that_is_still_on_cpu() {
    let _g = test_lock();
    WAITERS.lock().clear();
    let _ = crate::live::ttwu::wake_list_drain(0);
    let parent = Arc::new(Task::new(9103, "parent", SchedClass::Normal { weight: 1024 }));
    parent.cpu.store(0, Ordering::Release);
    install(&parent);

    // park_for_wait4 marks it Sleeping; the switch-off has NOT completed, so
    // the scheduler's `on_cpu` ownership flag is still set.
    unsafe { park_for_wait4(); }
    parent.on_cpu.store(true, Ordering::Release);
    assert_eq!(parent.state(), TaskState::Sleeping);

    wake_wait4_parent(parent.tid);

    // Pre-fix: `claim_wake` succeeds (it IS Sleeping) and the parent was
    // enqueued straight onto the caller's runqueue — an executing task in the
    // ready tree, which the next `schedule()` picks and whose `on_cpu` CAS
    // then fails ("schedule selected task already owned by another CPU").
    assert!(!parent.on_rq.load(Ordering::Acquire),
        "a parent still executing on a CPU must not be enqueued by its waker");
    let rq = runqueue::global().expect("installed");
    assert_eq!(rq.inner.lock().nr_running(), 0, "the ready tree must stay empty");

    let deferred = crate::live::ttwu::wake_list_drain(0);
    assert_eq!(deferred.len(), 1, "the wake must be deferred to the owner CPU's wake list");
    assert_eq!(deferred[0].tid, parent.tid);
    assert_eq!(parent.state(), TaskState::Runnable, "the wake itself is not lost");

    uninstall();
}

#[test]
fn take_wait4_waiters_detaches_only_the_matching_parent() {
    let mut waiters: Vec<Arc<Task>> = Vec::new();
    for tid in [9201u32, 9202, 9201, 9203] {
        waiters.push(Arc::new(Task::new(tid, "p", SchedClass::Normal { weight: 1024 })));
    }

    let taken = take_wait4_waiters(&mut waiters, 9201);

    assert_eq!(taken.len(), 2, "both registrations for the parent must be detached");
    assert!(taken.iter().all(|t| t.tid == 9201));
    assert_eq!(waiters.len(), 2);
    assert!(waiters.iter().all(|t| t.tid != 9201), "a matching entry was left behind");
    assert!(waiters.iter().any(|t| t.tid == 9202) && waiters.iter().any(|t| t.tid == 9203),
        "swap_remove walk dropped an unrelated waiter");
}

#[test]
fn take_wait4_waiters_is_a_no_op_for_an_unregistered_parent() {
    let mut waiters: Vec<Arc<Task>> = Vec::new();
    waiters.push(Arc::new(Task::new(9204, "p", SchedClass::Normal { weight: 1024 })));

    assert!(take_wait4_waiters(&mut waiters, 9999).is_empty());
    assert_eq!(waiters.len(), 1);
}
