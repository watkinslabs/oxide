use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::live::runqueue::Runqueue;
use crate::{SchedClass, SchedPolicy, Task};

const START: u64 = 1_000;
const TICK_NS: u64 = 10_000_000;

fn running_fifo() -> (Arc<Task>, Runqueue) {
    let task = Arc::new(Task::new(8_801, "fifo-account",
        SchedClass::Rt { prio: 70, policy: SchedPolicy::Fifo }));
    task.sched.se.exec_start.store(START, Ordering::Release);
    task.on_cpu.store(true, Ordering::Release);
    task.on_rq.store(true, Ordering::Release);
    let idle = Arc::new(Task::new(8_800, "idle", SchedClass::Idle));
    let rq = Runqueue::new(0, idle);
    // SAFETY: this test exclusively owns the local runqueue and both tasks.
    let _idle = unsafe { rq.swap_current(Arc::clone(&task)) };
    (task, rq)
}

#[test]
fn fifo_tick_charges_a_complete_delayed_interval_before_returning() {
    let (task, rq) = running_fifo();

    super::task_tick_with_clock(&task, &rq, || START + TICK_NS);
    super::task_tick_with_clock(&task, &rq, || START + 6 * TICK_NS);

    assert_eq!(task.sched.se.sum_exec_runtime.load(Ordering::Acquire), 6 * TICK_NS,
        "a delayed FIFO tick discarded uninterrupted runtime");
    assert_eq!(task.sched.se.exec_start.load(Ordering::Acquire), START + 6 * TICK_NS,
        "FIFO tick did not restart accounting before its policy return");
    assert!(!task.need_resched.load(Ordering::Acquire),
        "runtime accounting changed FIFO's no-timeslice policy");
}

#[test]
fn fifo_tick_establishes_an_uninitialised_stamp_without_false_runtime() {
    let (task, rq) = running_fifo();
    task.sched.se.exec_start.store(0, Ordering::Release);

    super::task_tick_with_clock(&task, &rq, || START);
    assert_eq!(task.sched.se.sum_exec_runtime.load(Ordering::Acquire), 0);
    assert_eq!(task.sched.se.exec_start.load(Ordering::Acquire), START);

    super::task_tick_with_clock(&task, &rq, || START + 4 * TICK_NS);
    assert_eq!(task.sched.se.sum_exec_runtime.load(Ordering::Acquire), 4 * TICK_NS);
}

#[test]
fn fifo_tick_rejects_a_backward_clock_without_moving_the_stamp() {
    let (task, rq) = running_fifo();
    let future = START + 2 * TICK_NS;
    task.sched.se.exec_start.store(future, Ordering::Release);

    super::task_tick_with_clock(&task, &rq, || START + TICK_NS);

    assert_eq!(task.sched.se.sum_exec_runtime.load(Ordering::Acquire), 0);
    assert_eq!(task.sched.se.exec_start.load(Ordering::Acquire), future,
        "a backwards clock moved the accounting baseline backwards");
}

#[test]
fn native_quantum_expiry_rotates_only_after_the_last_tick() {
    let task = Arc::new(Task::new(8_810, "nt-current",
        SchedClass::NtFixed { level: 8, quantum: 2 }));
    task.sched.se.exec_start.store(START, Ordering::Release);
    task.cpu.store(0, Ordering::Release);
    task.on_cpu.store(true, Ordering::Release);
    task.on_rq.store(true, Ordering::Release);
    let peer = Arc::new(Task::new(8_811, "nt-peer",
        SchedClass::NtFixed { level: 8, quantum: 2 }));
    let idle = Arc::new(Task::new(8_800, "idle", SchedClass::Idle));
    let rq = Runqueue::new(0, idle);
    let _idle = unsafe { rq.swap_current(Arc::clone(&task)) };
    {
        let mut inner = rq.inner.lock();
        assert!(inner.enqueue(Arc::clone(&peer)));
        rq.publish_nr_running(inner.nr_running());
    }

    super::task_tick_with_clock(&task, &rq, || START + TICK_NS);
    assert_eq!(task.sched.nt_snapshot().quantum_remaining, 1);
    assert!(!task.rt_requeue_tail.load(Ordering::Acquire));
    super::task_tick_with_clock(&task, &rq, || START + 2 * TICK_NS);
    assert_eq!(task.sched.nt_snapshot().quantum_remaining, 2);
    assert!(task.rt_requeue_tail.load(Ordering::Acquire));
    let mut inner = rq.inner.lock();
    inner.put_prev_task(Arc::clone(&task));
    assert_eq!(inner.pick_next_task().tid, peer.tid);
    assert_eq!(inner.pick_next_task().tid, task.tid);
}

#[test]
fn native_rotation_positive_control_detects_a_missing_tail_request() {
    let task = Arc::new(Task::new(8_812, "nt-current",
        SchedClass::NtFixed { level: 8, quantum: 1 }));
    let peer = Arc::new(Task::new(8_813, "nt-peer",
        SchedClass::NtFixed { level: 8, quantum: 1 }));
    let mut inner = crate::RunqueueInner::new(0,
        Arc::new(Task::new(8_800, "idle", SchedClass::Idle)));
    assert!(inner.enqueue(peer));
    task.rt_requeue_tail.store(false, Ordering::Release);
    inner.put_prev_task(Arc::clone(&task));
    assert_eq!(inner.pick_next_task().tid, task.tid,
        "positive control no longer detects a missing expiry rotation");
}
