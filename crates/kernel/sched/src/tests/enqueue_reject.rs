use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::deadline::{self, DlParams, DlSched};
use crate::{RunqueueInner, SchedClass, Task, TaskState};

fn idle(tid: u32) -> Arc<Task> { Arc::new(Task::new(tid, "idle", SchedClass::Idle)) }

fn rejected_deadline(tid: u32) -> Arc<Task> {
    const MS: u64 = 1_000_000;
    const PERIOD: u64 = 1_000_000 * MS;
    let task = Arc::new(Task::new(tid, "deadline", SchedClass::Deadline));
    let params = DlParams::from_request(MS, PERIOD, PERIOD, 0);
    task.sched.dl.set_params(&params);
    task.sched.dl.store_sched(&DlSched {
        runtime: 0,
        deadline: deadline::clock::now_ns().saturating_add(PERIOD),
        throttled: true,
        yielded: false,
        overrun: false,
    });
    task.set_state(TaskState::Sleeping);
    assert!(task.claim_wake());
    task.on_rq.begin_migration();
    task
}

#[test]
fn rejected_deadline_enqueue_clears_waking_and_migrating() {
    let mut rq = RunqueueInner::new(7, idle(700));
    let task = rejected_deadline(701);

    assert!(!rq.enqueue(Arc::clone(&task)));
    assert_eq!(task.state(), TaskState::Runnable);
    assert!(!task.on_rq.load(Ordering::Acquire));
    assert!(!task.on_class_rq.load(Ordering::Acquire));
    assert_eq!(rq.nr_running(), 0);
    deadline::replenish::disarm(&task);
}

#[test]
fn positive_control_deadline_rejection_alone_retains_transition_state() {
    let task = rejected_deadline(702);

    assert!(!deadline::live::on_wakeup_enqueue(&task));
    assert_eq!(task.state(), TaskState::Waking,
        "positive control no longer reproduces the pre-fix Waking leak");
    assert!(task.on_rq.is_migrating(Ordering::Acquire),
        "positive control no longer reproduces the pre-fix migration leak");
    deadline::replenish::disarm(&task);
}

#[test]
fn frozen_rejection_clears_waking_and_migrating() {
    let mut rq = RunqueueInner::new(8, idle(800));
    let task = Arc::new(Task::new(801, "frozen", SchedClass::Normal { weight: 1024 }));
    task.set_state(TaskState::Sleeping);
    assert!(task.claim_wake());
    task.on_rq.begin_migration();
    task.frozen.store(true, Ordering::Release);

    assert!(!rq.enqueue(Arc::clone(&task)));
    assert_eq!(task.state(), TaskState::Runnable);
    assert!(!task.on_rq.load(Ordering::Acquire));
    assert_eq!(rq.nr_running(), 0);
}

#[test]
fn duplicate_rejection_restores_existing_queued_owner() {
    let mut rq = RunqueueInner::new(9, idle(900));
    let task = Arc::new(Task::new(901, "queued", SchedClass::Normal { weight: 1024 }));
    assert!(rq.enqueue(Arc::clone(&task)));
    task.set_state(TaskState::Sleeping);
    assert!(task.claim_wake());
    task.on_rq.begin_migration();

    assert!(!rq.enqueue(Arc::clone(&task)));
    assert_eq!(task.state(), TaskState::Runnable);
    assert!(task.on_rq.is_queued(Ordering::Acquire));
    assert!(task.on_class_rq.load(Ordering::Acquire));
    assert_eq!(rq.nr_running(), 1);
}

#[test]
fn losing_cross_rq_enqueue_preserves_owner_cpu_until_a_real_move() {
    let mut source = RunqueueInner::new(10, idle(1_010));
    let mut contender = RunqueueInner::new(11, idle(1_011));
    let task = Arc::new(Task::new(1_012, "owned", SchedClass::Normal { weight: 1024 }));

    assert!(source.enqueue(Arc::clone(&task)));
    assert_eq!(task.cpu.load(Ordering::Acquire), 10);
    assert!(!contender.enqueue(Arc::clone(&task)));
    assert_eq!(task.cpu.load(Ordering::Acquire), 10,
        "losing queue rewrote canonical source ownership");
    assert_eq!(source.nr_running(), 1);
    assert_eq!(contender.nr_running(), 0);

    // Positive control: once the source directly detaches the embedded node,
    // a successful destination claim must publish the new CPU.
    let moved = source.remove_task(&task).expect("source owns queued task");
    assert!(contender.enqueue(moved));
    assert_eq!(task.cpu.load(Ordering::Acquire), 11);
    assert_eq!(source.nr_running(), 0);
    assert_eq!(contender.nr_running(), 1);
}

#[test]
fn runqueue_initializes_idle_cpu_before_queued_ownership() {
    let task = idle(1_000);
    assert_eq!(task.cpu.load(Ordering::Acquire), u16::MAX);
    assert!(!task.on_rq.load(Ordering::Acquire));

    let rq = RunqueueInner::new(37, Arc::clone(&task));

    assert_eq!(rq.cpu, 37);
    assert_eq!(task.cpu.load(Ordering::Acquire), 37);
    assert!(task.on_rq.is_queued(Ordering::Acquire));
}
