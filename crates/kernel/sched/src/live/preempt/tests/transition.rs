use super::*;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use crate::{Task, SchedClass, SchedPolicy};
use crate::live::{runqueue::Runqueue, rq_locate::{task_rq_lock_with, StableTaskGuard, SchedChange}};

const START: u64 = 1_000;
const NOW: u64 = 101_000;

fn running(class: SchedClass) -> (Arc<Task>, Runqueue) {
    let task = Arc::new(Task::new(9920, "tick-transition", class));
    task.cpu.store(0, Ordering::Release);
    task.on_cpu.store(true, Ordering::Release);
    task.on_rq.store(true, Ordering::Release);
    task.sched.se.exec_start.store(START, Ordering::Release);
    let rq = Runqueue::new(0, Arc::new(Task::new(9921, "idle", SchedClass::Idle)));
    // SAFETY: this fixture exclusively owns the runqueue and current reference.
    let _ = unsafe { rq.swap_current(Arc::clone(&task)) };
    (task, rq)
}

fn transition(task: &Arc<Task>, rq: &Runqueue, change: impl FnOnce(&Task)) {
    assert!(rq.inner.try_lock().is_some(), "tick inverted rq -> TaskPi");
    let StableTaskGuard::Owned(lock) = task_rq_lock_with(&|_| Some(rq), task) else {
        unreachable!()
    };
    let _change = SchedChange::from_lock(lock, task, START);
    change(task);
}

#[test]
fn fair_to_native_before_rq_dispatch_consumes_native_quantum() {
    let (task, rq) = running(SchedClass::Normal { weight: 1024 });
    task_tick_with_windows(&task, &rq, || {
        assert!(rq.inner.try_lock().is_none());
        assert!(task.pi_lock.try_lock().is_none(), "native mutation lacks TaskPi");
        NOW
    }, || transition(&task, &rq, |task| {
        task.sched.store_nt_unlocked(crate::nt::NtSchedSnapshot::new(8, 2));
    }), || {});
    assert_eq!(task.sched.nt_snapshot().quantum_remaining, 1);
    assert_eq!(task.sched.se.sum_exec_runtime.load(Ordering::Acquire), NOW - START);
}

#[test]
fn native_to_fifo_during_owner_reacquire_does_not_restore_native_policy() {
    let (task, rq) = running(SchedClass::NtFixed { level: 8, quantum: 2 });
    let fifo = SchedClass::Rt { prio: 70, policy: SchedPolicy::Fifo };
    task_tick_with_windows(&task, &rq, || NOW, || {}, || {
        transition(&task, &rq, |task| {
            task.sched.store_normal_class(fifo, crate::sched_enc::SCHED_FIFO);
        });
    });
    assert_eq!(task.sched_class(), fifo);
    assert_eq!(task.sched.nt_snapshot().quantum_remaining, 2);
    assert_eq!(task.sched.se.sum_exec_runtime.load(Ordering::Acquire), NOW - START);
}

#[test]
fn native_to_deadline_reacquire_charges_new_class_under_owner() {
    let (task, rq) = running(SchedClass::NtFixed { level: 8, quantum: 2 });
    task_tick_with_windows(&task, &rq, || {
        assert!(rq.inner.try_lock().is_none());
        assert!(task.pi_lock.try_lock().is_none());
        NOW
    }, || {}, || transition(&task, &rq, |task| {
        task.sched.dl.set_params(&crate::deadline::DlParams::from_request(
            1_000_000, 10_000_000, 10_000_000, 0));
        task.sched.dl.store_sched(&crate::deadline::DlSched {
            runtime: 1_000_000, deadline: 10_000_000, ..Default::default()
        });
        task.sched.dl.set_exec_start(START);
        task.sched.store_normal_class(SchedClass::Deadline, crate::sched_enc::SCHED_DEADLINE);
    }));
    assert_eq!(task.sched_class(), SchedClass::Deadline);
    assert_eq!(task.sched.dl.sched().runtime, 900_000);
    assert_eq!(task.sched.nt_snapshot().quantum_remaining, 2);
}
