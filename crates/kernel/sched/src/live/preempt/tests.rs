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
