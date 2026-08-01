// The deadline class as the runqueue actually sees it: class ordering, EDF
// pick order, and the throttle/replenish round trip on a live task.
//
// The hosted clock (`deadline::clock`) is settable, so the CBS edges are driven
// exactly rather than waited for.

extern crate alloc;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::deadline::{clock, live, params::DlParams, replenish};
use crate::dl::DlRunqueue;
use crate::runqueue::RunqueueInner;
use crate::task::{SchedClass, SchedPolicy, Task, TaskState};

const MS: u64 = 1_000_000;

/// The hosted clock and the replenishment queue are process-global; serialise
/// so parallel test execution does not observe another test's time.
fn dl_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// A deadline task holding `runtime` every `period`, started at the current
/// hosted clock.
fn dl_task(tid: u32, runtime: u64, deadline: u64, period: u64) -> Arc<Task> {
    let t = Arc::new(Task::new(tid, "dl", SchedClass::Deadline));
    t.policy.store(crate::sched_enc::SCHED_DEADLINE, Ordering::Release);
    live::enter_class(&t, &DlParams::from_request(runtime, deadline, period, 0));
    t
}

fn rt_task(tid: u32, prio: u8) -> Arc<Task> {
    Arc::new(Task::new(tid, "rt", SchedClass::Rt { prio, policy: SchedPolicy::Fifo }))
}

fn fair_task(tid: u32) -> Arc<Task> {
    Arc::new(Task::new(tid, "fair", SchedClass::Normal { weight: 1024 }))
}

fn rq() -> RunqueueInner {
    RunqueueInner::new(0, Arc::new(Task::new(999, "idle", SchedClass::Idle)))
}

#[test]
fn the_ready_set_picks_the_earliest_deadline() {
    let _g = dl_lock();
    clock::set_now_ns(0);
    let mut q = DlRunqueue::new();
    q.enqueue(dl_task(1, MS, 30 * MS, 30 * MS));
    q.enqueue(dl_task(2, MS, 10 * MS, 10 * MS));
    q.enqueue(dl_task(3, MS, 20 * MS, 20 * MS));
    assert_eq!(q.pick_earliest().unwrap().tid, 2);
    assert_eq!(q.pick_earliest().unwrap().tid, 3);
    assert_eq!(q.pick_earliest().unwrap().tid, 1);
    assert!(q.pick_earliest().is_none());
}

#[test]
fn the_earliest_deadline_is_reported_without_removing_it() {
    let _g = dl_lock();
    clock::set_now_ns(0);
    let mut q = DlRunqueue::new();
    let a = dl_task(1, MS, 20 * MS, 20 * MS);
    q.enqueue(Arc::clone(&a));
    q.enqueue(dl_task(2, MS, 40 * MS, 40 * MS));
    assert_eq!(q.earliest_deadline(), Some(a.dl.abs_deadline()));
    assert_eq!(q.peek_earliest().unwrap().tid, 1);
    assert_eq!(q.nr_running(), 2);
}

#[test]
fn a_deadline_task_outranks_every_real_time_priority_and_the_fair_class() {
    let _g = dl_lock();
    clock::set_now_ns(0);
    let mut r = rq();
    r.enqueue(fair_task(10));
    r.enqueue(rt_task(11, 99));
    // Deliberately the LATEST deadline available: class rank, not deadline
    // value, is what puts it ahead of the highest real-time priority.
    r.enqueue(dl_task(12, MS, 4_000 * MS, 4_000 * MS));
    assert_eq!(r.nr_running(), 3);
    assert_eq!(r.pick_next_task().tid, 12);
    assert_eq!(r.pick_next_task().tid, 11);
    assert_eq!(r.pick_next_task().tid, 10);
    // Nothing left: the idle task.
    assert_eq!(r.pick_next_task().tid, 999);
}

#[test]
fn a_task_that_overruns_its_budget_is_thrown_off_the_ready_set() {
    let _g = dl_lock();
    clock::set_now_ns(0);
    let mut r = rq();
    let t = dl_task(1, 2 * MS, 10 * MS, 10 * MS);
    r.enqueue(Arc::clone(&t));
    assert_eq!(r.nr_running(), 1);

    // Take the CPU, run for the whole budget, and be accounted on the way out.
    let picked = r.pick_next_task();
    assert_eq!(picked.tid, 1);
    live::set_next_task_dl(&picked, 0);
    clock::set_now_ns(2 * MS);
    assert_eq!(live::update_curr_dl(&picked, 2 * MS), crate::deadline::Charged::Throttle);
    assert!(t.dl.is_throttled());

    // `put_prev_task` must NOT return it to the ready set: an exhausted budget
    // is an enforcement, so the class is empty even though the task is runnable.
    r.put_prev_task(picked);
    assert_eq!(r.nr_running(), 0);
    assert_eq!(r.pick_next_task().tid, 999, "the CPU idles rather than overrun");

    // ... and a wakeup in the same instance does not smuggle it back in.
    r.enqueue(Arc::clone(&t));
    assert_eq!(r.nr_running(), 0);

    replenish::disarm(&t);
}

#[test]
fn a_throttled_task_is_replenished_at_the_start_of_its_next_period() {
    let _g = dl_lock();
    clock::set_now_ns(0);
    let mut r = rq();
    let t = dl_task(1, 2 * MS, 10 * MS, 10 * MS);
    let first_deadline = t.dl.abs_deadline();
    r.enqueue(Arc::clone(&t));
    let picked = r.pick_next_task();
    live::set_next_task_dl(&picked, 0);
    clock::set_now_ns(2 * MS);
    live::update_curr_dl(&picked, 2 * MS);
    r.put_prev_task(picked);

    // The replenishment instant is the start of the next period, and it is the
    // next timer event the class asks for.
    assert_eq!(t.dl.replenish_at(), first_deadline);
    assert_eq!(replenish::earliest_ns(), first_deadline);

    // Nothing is due before then.
    live::expire_throttled(first_deadline - 1);
    assert!(t.dl.is_throttled());

    clock::set_now_ns(first_deadline);
    live::expire_throttled(first_deadline);
    assert!(!t.dl.is_throttled());
    assert_eq!(t.dl.sched().runtime, 2 * MS as i64, "a full fresh budget");
    assert_eq!(t.dl.abs_deadline(), first_deadline + 10 * MS, "one period later");

    // Now it may run again.
    r.enqueue(Arc::clone(&t));
    assert_eq!(r.nr_running(), 1);
    assert_eq!(r.pick_next_task().tid, 1);
    replenish::disarm(&t);
}

#[test]
fn yielding_gives_up_the_instance_not_just_the_cpu() {
    let _g = dl_lock();
    clock::set_now_ns(0);
    let mut r = rq();
    let t = dl_task(1, 2 * MS, 10 * MS, 10 * MS);
    let first_deadline = t.dl.abs_deadline();
    r.enqueue(Arc::clone(&t));
    let picked = r.pick_next_task();
    live::set_next_task_dl(&picked, 0);

    // Yield after using almost none of the budget.
    clock::set_now_ns(100_000);
    r.yield_current_task(&picked);
    assert!(t.dl.is_throttled(), "the remaining budget is donated, not kept");

    r.put_prev_task(picked);
    assert_eq!(r.nr_running(), 0, "a yielded deadline task is not re-picked");

    // It comes back at the next period with a full grant — one period lost,
    // no more.
    clock::set_now_ns(first_deadline);
    live::expire_throttled(first_deadline);
    assert_eq!(t.dl.sched().runtime, 2 * MS as i64);
    assert_eq!(t.dl.abs_deadline(), first_deadline + 10 * MS);
    replenish::disarm(&t);
}

#[test]
fn a_sleeping_task_is_replenished_but_not_queued() {
    let _g = dl_lock();
    clock::set_now_ns(0);
    let t = dl_task(1, 2 * MS, 10 * MS, 10 * MS);
    let first_deadline = t.dl.abs_deadline();
    live::set_next_task_dl(&t, 0);
    clock::set_now_ns(2 * MS);
    live::update_curr_dl(&t, 2 * MS);
    assert!(live::on_requeue(&t) == false);
    t.set_state(TaskState::Sleeping);

    clock::set_now_ns(first_deadline);
    live::expire_throttled(first_deadline);
    assert!(!t.dl.is_throttled());
    assert_eq!(t.dl.sched().runtime, 2 * MS as i64);
    replenish::disarm(&t);
}

#[test]
fn a_replenishment_instant_already_past_replenishes_inline() {
    // Arming a timer for the past would leave the entity off the ready set
    // forever; it is replenished on the spot instead.
    let _g = dl_lock();
    clock::set_now_ns(0);
    let t = dl_task(1, 2 * MS, 10 * MS, 10 * MS);
    live::set_next_task_dl(&t, 0);
    clock::set_now_ns(2 * MS);
    live::update_curr_dl(&t, 2 * MS);
    // Jump well past the next period before the requeue decision runs.
    clock::set_now_ns(500 * MS);
    assert!(live::on_requeue(&t), "replenished inline, so it may queue at once");
    assert!(!t.dl.is_throttled());
    assert_eq!(t.dl.sched().runtime, 2 * MS as i64);
    assert!(t.dl.abs_deadline() > 500 * MS);
    replenish::disarm(&t);
}

#[test]
fn leaving_the_class_cancels_a_pending_replenishment() {
    let _g = dl_lock();
    clock::set_now_ns(0);
    let t = dl_task(1, 2 * MS, 10 * MS, 10 * MS);
    live::set_next_task_dl(&t, 0);
    clock::set_now_ns(2 * MS);
    live::update_curr_dl(&t, 2 * MS);
    live::on_requeue(&t);
    assert_ne!(replenish::earliest_ns(), u64::MAX);

    live::leave_class(&t);
    assert_eq!(replenish::earliest_ns(), u64::MAX);
    assert_eq!(t.dl.params().runtime, 0);
    assert!(!t.dl.is_throttled());
}

#[test]
fn a_wakeup_never_hands_back_more_budget_than_the_reservation_allows() {
    let _g = dl_lock();
    clock::set_now_ns(0);
    let t = dl_task(1, 2 * MS, 10 * MS, 10 * MS);
    // Sleep nearly the whole instance without running: the untouched budget
    // against the remaining laxity is a density far above what was admitted, so
    // the wakeup starts a new instance rather than letting it run flat out.
    clock::set_now_ns(9 * MS + 500_000);
    assert!(live::on_wakeup_enqueue(&t));
    assert_eq!(t.dl.abs_deadline(), 9 * MS + 500_000 + 10 * MS);
    assert_eq!(t.dl.sched().runtime, 2 * MS as i64);
}

#[test]
fn a_deadline_task_confined_below_the_span_is_refused() {
    let t = dl_task(1, MS, 10 * MS, 10 * MS);
    let span = crate::deadline::span();
    assert!(!live::confined_below_span(&t, span));
    assert!(!live::confined_below_span(&t, u64::MAX));
    assert!(live::confined_below_span(&t, span & !1 | 0));
    // A fair task is never subject to the rule.
    assert!(!live::confined_below_span(&fair_task(2), 0));
}
