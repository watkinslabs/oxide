use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::deadline::{DlParams, DlSched};
use crate::live::rq_locate::{SchedChange, StableTaskGuard, task_rq_lock_with};
use crate::live::runqueue::Runqueue;
use crate::{SchedClass, SchedPolicy, Task};

const CPU: u32 = 3;
const START: u64 = 10;
const CHANGE: u64 = 20;
const NEXT: u64 = 25;
const DL_RUNTIME: u64 = 1_000;
const DL_WINDOW: u64 = 10_000;

fn running(tid: u32, class: SchedClass) -> (Arc<Task>, Runqueue) {
    let task = Arc::new(Task::new(tid, "changing", class));
    task.cpu.store(CPU as u16, Ordering::Release);
    task.on_cpu.store(true, Ordering::Release);
    task.on_rq.store(true, Ordering::Release);
    let idle = Arc::new(Task::new(9_000 + tid, "idle", SchedClass::Idle));
    let rq = Runqueue::new(CPU as u16, idle);
    // SAFETY: this test exclusively owns the runqueue and its current slot.
    let _idle = unsafe { rq.swap_current(Arc::clone(&task)) };
    (task, rq)
}

fn install_dl(task: &Task) {
    let params = DlParams::from_request(DL_RUNTIME, DL_WINDOW, DL_WINDOW, 0);
    task.sched.dl.set_params(&params);
    task.sched.dl.store_sched(&DlSched { runtime: DL_RUNTIME as i64,
        deadline: DL_WINDOW, throttled: false, yielded: false, overrun: false });
}

fn change(task: &Arc<Task>, rq: &Runqueue, class: SchedClass) {
    let StableTaskGuard::Owned(lock) = task_rq_lock_with(
        &|cpu| if cpu == CPU { Some(rq) } else { None }, task)
    else { panic!("running task lost its runqueue") };
    let transaction = SchedChange::from_lock(lock, task, CHANGE);
    if matches!(class, SchedClass::Deadline) {
        task.apply_sched_update_unlocked(crate::SchedUpdate {
            class, policy: crate::sched_enc::SCHED_DEADLINE,
            clamp: crate::SchedUclamp::new(0,
                crate::sched_enc::UCLAMP_CAPACITY_SCALE, 0).unwrap(),
            reset_on_fork: false, nice: None, fair_slice: None,
            reload_rt_timeslice: false, clear_rt_timeout: false,
            deadline: Some(DlParams::from_request(
                DL_RUNTIME, DL_WINDOW, DL_WINDOW, 0)),
        });
    } else {
        task.sched.store_effective_class(class);
    }
    drop(transaction);
}

fn account(task: &Task, rq: &Runqueue, now: u64) {
    let inner = rq.inner.lock();
    super::super::handoff::update_curr(task, &inner, now);
}

fn total(task: &Task) -> u64 {
    task.sched.se.sum_exec_runtime.load(Ordering::Acquire)
}

fn dl_left(task: &Task) -> i64 { task.sched.dl.sched().runtime }

#[test]
fn deadline_to_fair_next_pass_charges_only_the_new_interval_once() {
    let (task, rq) = running(9_101, SchedClass::Deadline);
    install_dl(&task);
    task.sched.dl.set_exec_start(START);
    task.sched.se.exec_start.store(1, Ordering::Release);

    change(&task, &rq, SchedClass::Normal { weight: 1_024 });
    assert_eq!(total(&task), CHANGE - START, "old Deadline interval was not settled");
    let dl_after_change = dl_left(&task);
    account(&task, &rq, NEXT);
    assert_eq!(total(&task), NEXT - START, "first Fair pass charged the wrong interval");
    assert_eq!(task.sched.se.vruntime.load(Ordering::Acquire), NEXT - CHANGE,
        "first Fair pass did not charge Fair vruntime");
    assert_eq!(dl_left(&task), dl_after_change, "Fair pass charged stale Deadline budget");
    account(&task, &rq, NEXT);
    assert_eq!(total(&task), NEXT - START, "same Fair interval was charged twice");
    assert_eq!(dl_left(&task), dl_after_change, "repeat Fair pass charged Deadline budget");
}

#[test]
fn deadline_to_rt_next_pass_charges_only_the_new_interval_once() {
    let (task, rq) = running(9_102, SchedClass::Deadline);
    install_dl(&task);
    task.sched.dl.set_exec_start(START);
    task.sched.se.exec_start.store(1, Ordering::Release);

    change(&task, &rq, SchedClass::Rt { prio: 20, policy: SchedPolicy::Fifo });
    assert_eq!(total(&task), CHANGE - START, "old Deadline interval was not settled");
    let dl_after_change = dl_left(&task);
    account(&task, &rq, NEXT);
    assert_eq!(total(&task), NEXT - START, "first RT pass charged the wrong interval");
    assert_eq!(task.sched.se.vruntime.load(Ordering::Acquire), 0,
        "RT execution incorrectly advanced Fair vruntime");
    assert_eq!(dl_left(&task), dl_after_change, "RT pass charged stale Deadline budget");
    account(&task, &rq, NEXT);
    assert_eq!(total(&task), NEXT - START, "same RT interval was charged twice");
    assert_eq!(dl_left(&task), dl_after_change, "repeat RT pass charged Deadline budget");
}

#[test]
fn fair_to_deadline_next_pass_charges_only_the_new_interval_once() {
    let (task, rq) = running(9_103, SchedClass::Normal { weight: 1_024 });
    task.sched.se.exec_start.store(START, Ordering::Release);

    change(&task, &rq, SchedClass::Deadline);
    assert_eq!(total(&task), CHANGE - START, "old Fair interval was not settled");
    assert_eq!(task.sched.se.vruntime.load(Ordering::Acquire), CHANGE - START,
        "old Fair interval did not reach Fair vruntime");
    account(&task, &rq, NEXT);
    assert_eq!(total(&task), NEXT - START, "first Deadline pass charged the wrong interval");
    assert_eq!(dl_left(&task), (DL_RUNTIME - (NEXT - CHANGE)) as i64,
        "first Deadline pass charged the wrong CBS budget");
    account(&task, &rq, NEXT);
    assert_eq!(total(&task), NEXT - START, "same Deadline interval was charged twice");
    assert_eq!(dl_left(&task), (DL_RUNTIME - (NEXT - CHANGE)) as i64,
        "same Deadline interval was charged twice to CBS");
}

#[test]
fn rt_to_deadline_next_pass_charges_only_the_new_interval_once() {
    let (task, rq) = running(9_104,
        SchedClass::Rt { prio: 20, policy: SchedPolicy::Fifo });
    task.sched.se.exec_start.store(START, Ordering::Release);

    change(&task, &rq, SchedClass::Deadline);
    assert_eq!(total(&task), CHANGE - START, "old RT interval was not settled");
    assert_eq!(task.sched.se.vruntime.load(Ordering::Acquire), 0,
        "old RT interval incorrectly reached Fair vruntime");
    account(&task, &rq, NEXT);
    assert_eq!(total(&task), NEXT - START, "first Deadline pass charged the wrong interval");
    assert_eq!(dl_left(&task), (DL_RUNTIME - (NEXT - CHANGE)) as i64,
        "first Deadline pass charged the wrong CBS budget");
    account(&task, &rq, NEXT);
    assert_eq!(total(&task), NEXT - START, "same Deadline interval was charged twice");
    assert_eq!(dl_left(&task), (DL_RUNTIME - (NEXT - CHANGE)) as i64,
        "same Deadline interval was charged twice to CBS");
}
