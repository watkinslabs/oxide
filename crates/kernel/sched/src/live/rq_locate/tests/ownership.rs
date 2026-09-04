// A task queued on a REMOTE CPU's runqueue must be re-placed there, never
// duplicated onto the caller's runqueue.
//
// These build real `Runqueue` instances locally rather than installing into
// `GLOBALS` — that array only accepts writes for `this_cpu()` (always 0
// hosted) and is process-global, so parallel `cargo test` threads would
// collide. The accessor closure supplies the CPU->rq mapping instead, which is
// exactly what `global_for` does in production.

use super::*;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use crate::runqueue::RunqueueInner;
use crate::task::{SchedClass, SchedPolicy, Task};

#[test]
fn sanity_enqueue_puts_task_in_exactly_one_tree() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    let t = normal_task(7);
    enqueue_on(&cpus, REMOTE_CPU, t.clone());
    assert_eq!(cpus.trees_holding(7), 1);
    assert!(t.on_rq.load(Ordering::Acquire));
}

/// The core hazard: `set_class` on a task sitting on ANOTHER CPU's runqueue
/// must not leave the same `Arc` in two trees. Pre-fix this failed with the
/// task present in both the remote tree and the caller's tree — two CPUs could
/// then pick and run it simultaneously.
#[test]
fn set_class_on_remote_queued_task_never_double_enqueues() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    let t = normal_task(11);
    enqueue_on(&cpus, REMOTE_CPU, t.clone());

    change_class(&cpus, &t, SchedClass::Rt { prio: 50, policy: SchedPolicy::Fifo });

    assert_eq!(cpus.trees_holding(11), 1,
        "task is queued on more than one runqueue: two CPUs can run it at once");
}

/// It must stay on the runqueue it was already on — re-placing it on the
/// caller's CPU is an unauthorised migration (Linux `sched_change_end` uses
/// `task_rq(p)`).
#[test]
fn set_class_keeps_the_task_on_its_own_runqueue() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    let t = normal_task(12);
    enqueue_on(&cpus, REMOTE_CPU, t.clone());

    change_class(&cpus, &t, SchedClass::Rt { prio: 20, policy: SchedPolicy::Fifo });

    let remote = cpus.get(REMOTE_CPU).unwrap();
    let caller = cpus.get(CALLER_CPU).unwrap();
    assert_eq!(remote.inner.lock().nr_running(), 1, "task left its own runqueue");
    assert_eq!(caller.inner.lock().nr_running(), 0, "task was migrated to the caller's CPU");
}

#[test]
fn set_class_actually_applies_the_new_class() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    let t = normal_task(13);
    enqueue_on(&cpus, REMOTE_CPU, t.clone());

    change_class(&cpus, &t, SchedClass::Rt { prio: 42, policy: SchedPolicy::Fifo });

    assert!(matches!(t.sched_class(), SchedClass::Rt { prio: 42, .. }),
        "class change was lost");
    assert!(t.on_rq.load(Ordering::Acquire), "task must be back on a runqueue");
}

/// The requeue must land in the tree belonging to the NEW class, so the
/// scheduler finds it where it now belongs.
#[test]
fn set_class_requeues_into_the_new_class_tree() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    let t = normal_task(14);
    enqueue_on(&cpus, REMOTE_CPU, t.clone());

    change_class(&cpus, &t, SchedClass::Rt { prio: 60, policy: SchedPolicy::Fifo });

    let remote = cpus.get(REMOTE_CPU).unwrap();
    let mut inner = remote.inner.lock();
    let picked = inner.pick_next_task();
    assert_eq!(picked.tid, 14, "the requeued task was not picked");
    assert!(matches!(picked.sched_class(), SchedClass::Rt { .. }),
        "task was not requeued into the RT tree");
}

/// A task queued nowhere (blocked, or currently running) only gets its class
/// updated — Linux's `ctx->queued` idempotence. It must NOT be enqueued.
#[test]
fn set_class_on_unqueued_task_does_not_enqueue_it() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    let t = normal_task(15);
    t.set_state(crate::TaskState::Sleeping);
    assert!(!t.on_rq.load(Ordering::Acquire));

    change_class(&cpus, &t, SchedClass::Rt { prio: 10, policy: SchedPolicy::Fifo });

    assert_eq!(cpus.trees_holding(15), 0, "an unqueued task was enqueued by a class change");
    assert!(matches!(t.sched_class(), SchedClass::Rt { prio: 10, .. }));
    assert!(!t.on_rq.load(Ordering::Acquire));
}

/// Changing to Idle removes the task from the runqueues (idle never queues).
#[test]
fn set_class_to_idle_leaves_no_tree_holding_it() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    let t = normal_task(16);
    enqueue_on(&cpus, REMOTE_CPU, t.clone());

    change_class(&cpus, &t, SchedClass::Idle);

    assert_eq!(cpus.trees_holding(16), 0, "idle task must not sit on a class tree");
    assert!(!t.on_rq.load(Ordering::Acquire),
        "a task rejected from every class tree must not remain canonically queued");
}

#[test]
fn priority_increase_joins_equal_rt_peers_at_tail() {
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let peer = Arc::new(Task::new(20, "peer",
        SchedClass::Rt { prio: 30, policy: SchedPolicy::Fifo }));
    let changed = Arc::new(Task::new(21, "changed",
        SchedClass::Rt { prio: 20, policy: SchedPolicy::Fifo }));
    enqueue_on(&cpus, REMOTE_CPU, peer);
    enqueue_on(&cpus, REMOTE_CPU, Arc::clone(&changed));

    change_class(&cpus, &changed,
        SchedClass::Rt { prio: 30, policy: SchedPolicy::Fifo });

    let rq = cpus.get(REMOTE_CPU).unwrap();
    let mut inner = rq.inner.lock();
    assert_eq!(inner.pick_next_task().tid, 20,
        "a userspace priority increase jumped ahead of an equal FIFO peer");
    assert_eq!(inner.pick_next_task().tid, 21);
}

#[test]
fn fifo_to_rr_change_at_equal_priority_preserves_exact_position() {
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let changed = Arc::new(Task::new(26, "changed",
        SchedClass::Rt { prio: 30, policy: SchedPolicy::Fifo }));
    let peer = Arc::new(Task::new(25, "peer",
        SchedClass::Rt { prio: 30, policy: SchedPolicy::Fifo }));
    enqueue_on(&cpus, REMOTE_CPU, Arc::clone(&changed));
    enqueue_on(&cpus, REMOTE_CPU, peer);

    let update = crate::SchedUpdate {
        class: SchedClass::Rt { prio: 30, policy: SchedPolicy::Rr },
        policy: crate::sched_enc::SCHED_RR,
        clamp: crate::SchedUclamp::new(0, crate::sched_enc::UCLAMP_CAPACITY_SCALE, 0).unwrap(),
        reset_on_fork: false, nice: None, fair_slice: None,
        reload_rt_timeslice: true, clear_rt_timeout: true, deadline: None,
    };
    let StableTaskGuard::Owned(lock) = task_rq_lock_with(&|c| cpus.get(c), &changed)
        else { panic!("queued task must return its owning runqueue") };
    let move_queued = changed.sched_update_moves_queue(update);
    let _change = SchedChange::from_lock_mode(lock, &changed, 0, move_queued);
    changed.apply_sched_update_unlocked(update);
    drop(_change);

    let rq = cpus.get(REMOTE_CPU).unwrap();
    let mut inner = rq.inner.lock();
    assert_eq!(inner.pick_next_task().tid, 26,
        "equal-priority FIFO-to-RR change lost its exact saved position");
    assert_eq!(inner.pick_next_task().tid, 25);
}

#[test]
fn positive_control_fifo_rr_tail_reinsert_loses_saved_position() {
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let changed = Arc::new(Task::new(27, "changed",
        SchedClass::Rt { prio: 30, policy: SchedPolicy::Fifo }));
    let peer = Arc::new(Task::new(28, "peer",
        SchedClass::Rt { prio: 30, policy: SchedPolicy::Fifo }));
    enqueue_on(&cpus, REMOTE_CPU, Arc::clone(&changed));
    enqueue_on(&cpus, REMOTE_CPU, peer);

    let rq = cpus.get(REMOTE_CPU).unwrap();
    let mut inner = rq.inner.lock();
    let moved = inner.remove(changed.tid).expect("changed task queued");
    changed.sched.store_effective_class(
        SchedClass::Rt { prio: 30, policy: SchedPolicy::Rr });
    assert!(inner.enqueue_at(moved, crate::sched_enc::requeue::RequeuePos::Tail));

    assert_eq!(inner.pick_next_task().tid, 28,
        "positive control no longer reproduces FIFO/RR tail-reinsert reorder");
}

#[test]
fn enqueue_wrapper_reports_rejection_and_clears_transition_state() {
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let task = normal_task(29);
    task.set_state(crate::TaskState::Sleeping);
    assert!(task.claim_wake());
    task.on_rq.begin_migration();
    task.frozen.store(true, Ordering::Release);

    assert!(!enqueue_on_with(&|c| cpus.get(c), REMOTE_CPU, Arc::clone(&task)));
    assert_eq!(task.state(), crate::TaskState::Runnable);
    assert!(!task.on_rq.load(Ordering::Acquire));
    assert_eq!(cpus.trees_holding(task.tid), 0);
}

#[test]
fn missing_destination_rejection_clears_transition_state() {
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let task = normal_task(30);
    task.set_state(crate::TaskState::Sleeping);
    assert!(task.claim_wake());
    task.on_rq.begin_migration();

    assert!(!enqueue_on_with(&|c| cpus.get(c), 63, Arc::clone(&task)));
    assert_eq!(task.state(), crate::TaskState::Runnable);
    assert!(!task.on_rq.load(Ordering::Acquire));
}

#[test]
fn queued_promotion_marks_remote_current_for_preemption() {
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let current = Arc::new(Task::new(22, "current",
        SchedClass::Rt { prio: 10, policy: SchedPolicy::Fifo }));
    current.on_cpu.store(true, Ordering::Release);
    current.on_rq.store(true, Ordering::Release);
    let wakee = normal_task(23);
    let rq = cpus.get(REMOTE_CPU).unwrap();
    // SAFETY: the hosted test exclusively owns this runqueue.
    let _idle = unsafe { rq.swap_current(Arc::clone(&current)) };
    enqueue_on(&cpus, REMOTE_CPU, Arc::clone(&wakee));

    change_class(&cpus, &wakee,
        SchedClass::Rt { prio: 99, policy: SchedPolicy::Fifo });

    assert!(current.need_resched.load(Ordering::Acquire),
        "promoting queued work above rq->curr did not request preemption");
}

#[test]
fn running_change_accounts_elapsed_time_before_reweighting() {
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let current = normal_task(24);
    current.cpu.store(REMOTE_CPU as u16, Ordering::Release);
    current.on_cpu.store(true, Ordering::Release);
    current.on_rq.store(true, Ordering::Release);
    current.sched.se.exec_start.store(10, Ordering::Release);
    let rq = cpus.get(REMOTE_CPU).unwrap();
    // SAFETY: the hosted test exclusively owns this runqueue.
    let _idle = unsafe { rq.swap_current(Arc::clone(&current)) };
    let peer = normal_task(25);
    enqueue_on(&cpus, REMOTE_CPU, peer);

    {
        let StableTaskGuard::Owned(lock) = task_rq_lock_with(&|c| cpus.get(c), &current)
            else { panic!("running task must return its owning runqueue") };
        let _change = SchedChange::from_lock(lock, &current, 20);
        current.sched.store_nice(-20);
    }

    assert_eq!(current.sched.se.sum_exec_runtime.load(Ordering::Acquire), 10,
        "elapsed execution was not settled before the weight mutation");
    assert_eq!(current.sched.se.vruntime.load(Ordering::Acquire), 10,
        "elapsed execution was retroactively charged at the new weight");
    assert!(current.need_resched.load(Ordering::Acquire));
}

#[test]
fn running_deadline_to_fair_restarts_new_class_accounting_clock() {
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let current = deadline_task(26, 30_000_000);
    current.cpu.store(REMOTE_CPU as u16, Ordering::Release);
    current.on_cpu.store(true, Ordering::Release);
    current.on_rq.store(true, Ordering::Release);
    current.sched.dl.set_exec_start(10);
    current.sched.se.exec_start.store(3, Ordering::Release);
    let rq = cpus.get(REMOTE_CPU).unwrap();
    // SAFETY: the hosted test exclusively owns this runqueue.
    let _idle = unsafe { rq.swap_current(Arc::clone(&current)) };

    {
        let StableTaskGuard::Owned(lock) = task_rq_lock_with(&|c| cpus.get(c), &current)
            else { panic!("running task must return its owning runqueue") };
        let _change = SchedChange::from_lock(lock, &current, 20);
        current.sched.store_effective_class(SchedClass::Normal { weight: 1024 });
    }

    assert_eq!(current.sched.se.exec_start.load(Ordering::Acquire), 20,
        "new Fair class retained the stale pre-Deadline execution stamp");
}

#[test]
fn off_rq_result_retains_task_pi_until_the_caller_finishes() {
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let task = normal_task(31);
    task.set_state(crate::TaskState::Sleeping);
    let stable = task_rq_lock_with(&|c| cpus.get(c), &task);
    assert!(matches!(stable, StableTaskGuard::OffRq(_)));
    assert!(task.pi_lock.try_lock().is_none(), "OffRq proof dropped TaskPi early");
    drop(stable);
    assert!(task.pi_lock.try_lock().is_some(), "TaskPi stayed locked after result drop");
}

#[test]
fn owned_task_without_an_installed_rq_fails_loudly() {
    let task = normal_task(32);
    task.cpu.store(REMOTE_CPU as u16, Ordering::Release);
    task.on_rq.store(true, Ordering::Release);
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = task_rq_lock_with(&|_| None, &task);
    }));
    assert!(failed.is_err(), "owned task silently fell back to an unlocked mutation");
}

#[test]
fn dequeue_from_owning_rq_reports_the_right_cpu() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    let t = normal_task(17);
    enqueue_on(&cpus, REMOTE_CPU, t.clone());

    let (got, cpu) = dequeue_from_owning_rq_with(&|c| cpus.get(c), 17).expect("task located");
    assert_eq!(got.tid, 17);
    assert_eq!(cpu, REMOTE_CPU, "located the wrong runqueue");
    assert!(got.on_rq.is_queued(Ordering::Acquire),
        "class removal must preserve canonical runnable state");
    assert!(!got.on_class_rq.load(Ordering::Acquire),
        "remove must clear class-tree membership");
    assert_eq!(cpus.trees_holding(17), 0);
}

#[test]
fn dequeue_from_owning_rq_is_none_when_unqueued() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    assert!(dequeue_from_owning_rq_with(&|c| cpus.get(c), 999).is_none());
}

/// Reproduces the pre-fix algorithm literally — clear class membership, then enqueue on
/// the CALLER's runqueue without dequeuing from the task's real one — and
/// asserts the probe used by the tests above actually detects the resulting
/// double-enqueue. Without this, a broken probe would make those tests vacuous.
#[test]
fn queue_identity_rejects_the_pre_fix_membership_bit_bypass() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    let t = normal_task(18);
    enqueue_on(&cpus, REMOTE_CPU, t.clone());

    // Pre-fix `set_class` body, verbatim in effect:
    let caller = cpus.get(CALLER_CPU).unwrap();
    let mut inner = caller.inner.lock();
    let was_queued = t.on_rq.load(Ordering::Acquire);
    assert!(was_queued);
    inner.remove(t.tid);                       // finds nothing: wrong rq
    t.on_class_rq.store(false, Ordering::Release); // old boolean-only bypass
    assert!(!inner.enqueue(t.clone()));        // owner identity still rejects it
    drop(inner);

    t.on_class_rq.store(true, Ordering::Release);
    assert_eq!(cpus.trees_holding(18), 1,
        "queue identity allowed one embedded node into two runqueues");
}

/// `RunqueueInner`'s class-membership guard is what the pre-fix code defeated;
/// confirm it rejects a second enqueue when membership is left alone.
#[test]
fn enqueue_guard_rejects_a_second_enqueue_when_membership_is_respected() {
    let mut inner = RunqueueInner::new(0, Arc::new(Task::new(900, "idle", SchedClass::Idle)));
    let t = normal_task(19);
    assert!(inner.enqueue(t.clone()));
    assert!(!inner.enqueue(t.clone()));
    assert_eq!(inner.nr_running(), 1, "class-tree guard failed to block a double-enqueue");
}
