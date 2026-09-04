// The deadline class as the runqueue actually sees it: class ordering, EDF
// pick order, and the throttle/replenish round trip on a live task.
//
// The hosted clock (`deadline::clock`) is settable, so the CBS edges are driven
// exactly rather than waited for.

extern crate alloc;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Barrier, Condvar, Mutex};
use std::sync::mpsc::{self, Receiver};

use crate::deadline::{clock, live, params::DlParams, replenish};
use crate::dl::DlRunqueue;
use crate::runqueue::RunqueueInner;
use crate::task::{SchedClass, SchedPolicy, Task, TaskState};

const MS: u64 = 1_000_000;

/// The hosted clock and the replenishment queue are process-global; serialise
/// so parallel test execution does not observe another test's time.
struct DlGlobal(std::sync::MutexGuard<'static, ()>);
impl Drop for DlGlobal {
    fn drop(&mut self) {
        super::inactive::clear_for_tests();
        replenish::clear_for_tests();
        crate::deadline::bw::DL_BW.release(crate::deadline::bw::DL_BW.total_bw());
    }
}

fn dl_lock() -> DlGlobal {
    let guard = crate::tests::common::hosted_global_test_lock();
    super::inactive::clear_for_tests();
    replenish::clear_for_tests();
    crate::deadline::bw::init_default();
    crate::deadline::bw::DL_BW.release(crate::deadline::bw::DL_BW.total_bw());
    DlGlobal(guard)
}

/// A deadline task holding `runtime` every `period`, started at the current
/// hosted clock.
fn dl_task(tid: u32, runtime: u64, deadline: u64, period: u64) -> Arc<Task> {
    let t = Arc::new(Task::new(tid, "dl", SchedClass::Deadline));
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
    assert_eq!(q.earliest_deadline(), Some(a.sched.dl.abs_deadline()));
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
    assert!(t.sched.dl.is_throttled());

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
    let first_deadline = t.sched.dl.abs_deadline();
    r.enqueue(Arc::clone(&t));
    let picked = r.pick_next_task();
    live::set_next_task_dl(&picked, 0);
    clock::set_now_ns(2 * MS);
    live::update_curr_dl(&picked, 2 * MS);
    r.put_prev_task(picked);

    // The replenishment instant is the start of the next period, and it is the
    // next timer event the class asks for.
    assert_eq!(t.sched.dl.replenish_at(), first_deadline);
    assert_eq!(replenish::earliest_ns(), first_deadline);

    // Nothing is due before then.
    live::expire_throttled(first_deadline - 1);
    assert!(t.sched.dl.is_throttled());

    clock::set_now_ns(first_deadline);
    live::expire_throttled(first_deadline);
    assert!(!t.sched.dl.is_throttled());
    assert_eq!(t.sched.dl.sched().runtime, 2 * MS as i64, "a full fresh budget");
    assert_eq!(t.sched.dl.abs_deadline(), first_deadline + 10 * MS, "one period later");

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
    let first_deadline = t.sched.dl.abs_deadline();
    r.enqueue(Arc::clone(&t));
    let picked = r.pick_next_task();
    live::set_next_task_dl(&picked, 0);

    // Yield after using almost none of the budget.
    clock::set_now_ns(100_000);
    r.yield_current_task(&picked);
    assert!(t.sched.dl.is_throttled(), "the remaining budget is donated, not kept");

    r.put_prev_task(picked);
    assert_eq!(r.nr_running(), 0, "a yielded deadline task is not re-picked");

    // It comes back at the next period with a full grant — one period lost,
    // no more.
    clock::set_now_ns(first_deadline);
    live::expire_throttled(first_deadline);
    assert_eq!(t.sched.dl.sched().runtime, 2 * MS as i64);
    assert_eq!(t.sched.dl.abs_deadline(), first_deadline + 10 * MS);
    replenish::disarm(&t);
}

#[test]
fn a_sleeping_task_is_replenished_but_not_queued() {
    let _g = dl_lock();
    clock::set_now_ns(0);
    let t = dl_task(1, 2 * MS, 10 * MS, 10 * MS);
    let first_deadline = t.sched.dl.abs_deadline();
    live::set_next_task_dl(&t, 0);
    clock::set_now_ns(2 * MS);
    live::update_curr_dl(&t, 2 * MS);
    assert!(live::on_requeue(&t) == false);
    t.set_state(TaskState::Sleeping);

    clock::set_now_ns(first_deadline);
    live::expire_throttled(first_deadline);
    assert!(!t.sched.dl.is_throttled());
    assert_eq!(t.sched.dl.sched().runtime, 2 * MS as i64);
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
    assert!(!t.sched.dl.is_throttled());
    assert_eq!(t.sched.dl.sched().runtime, 2 * MS as i64);
    assert!(t.sched.dl.abs_deadline() > 500 * MS);
    replenish::disarm(&t);
}

#[test]
fn leaving_the_class_cancels_a_pending_replenishment() {
    let _g = dl_lock();
    clock::set_now_ns(0);
    let t = dl_task(1, 2 * MS, 10 * MS, 10 * MS);
    crate::deadline::bw::DL_BW.admit(crate::deadline::bw::capacity_of(64),
        true, false, 0, t.sched.dl.bw(), false).expect("fixture reservation fits");
    live::set_next_task_dl(&t, 0);
    clock::set_now_ns(2 * MS);
    live::update_curr_dl(&t, 2 * MS);
    live::on_requeue(&t);
    assert_ne!(replenish::earliest_ns(), u64::MAX);

    live::leave_class(&t);
    assert_eq!(t.sched.dl.replenish_at(), 0, "throttle replenishment was cancelled");
    assert_eq!(t.sched.dl.params().runtime, 2 * MS,
        "static parameters remain while the booking awaits zero lag");
    assert!(t.sched.dl.inactive_at() != 0);
    assert_eq!(replenish::earliest_ns(), t.sched.dl.inactive_at(),
        "hardware deadline folds in inactive expiry");
    live::expire_throttled(t.sched.dl.inactive_at());
    assert_eq!(t.sched.dl.params().runtime, 0);
}

struct LeaveBarrierReset;

impl Drop for LeaveBarrierReset {
    fn drop(&mut self) {
        live::set_leave_claim_gate(None);
        live::set_reset_gate(None);
    }
}

#[test]
fn stale_load_then_release_positive_control_double_subtracts() {
    let p = DlParams::from_request(2 * MS, 10 * MS, 10 * MS, 0);
    let t = Arc::new(Task::new(80, "dl", SchedClass::Deadline));
    t.sched.dl.set_params(&p);
    let total = Arc::new(AtomicU64::new(p.bw * 2));
    let loaded = Arc::new(Barrier::new(2));
    let mut workers = alloc::vec::Vec::new();
    for _ in 0..2 {
        let t = Arc::clone(&t);
        let total = Arc::clone(&total);
        let loaded = Arc::clone(&loaded);
        workers.push(std::thread::spawn(move || {
            let stale = t.sched.dl.bw();
            loaded.wait();
            total.fetch_update(Ordering::AcqRel, Ordering::Acquire,
                |v| Some(v.saturating_sub(stale))).unwrap();
        }));
    }
    for worker in workers { worker.join().unwrap(); }
    assert_eq!(total.load(Ordering::Acquire), 0,
        "control must erase the unrelated reservation");
}

#[test]
fn concurrent_exit_and_policy_leave_release_a_reservation_once() {
    let _g = dl_lock();
    let p = DlParams::from_request(2 * MS, 10 * MS, 10 * MS, 0);
    let baseline = crate::deadline::bw::DL_BW.total_bw();
    let cap = crate::deadline::bw::capacity_of(64);
    crate::deadline::bw::DL_BW.admit(cap, true, false, 0, p.bw, false)
        .expect("task reservation fits");
    crate::deadline::bw::DL_BW.admit(cap, true, false, 0, p.bw, false)
        .expect("control reservation fits");
    let t = Arc::new(Task::new(81, "dl", SchedClass::Deadline));
    t.set_state(TaskState::Sleeping);
    clock::set_now_ns(0);
    live::enter_class(&t, &p);
    clock::set_now_ns(1);

    let entered = Arc::new(Barrier::new(3));
    let expected = t.sched_policy_generation();
    let exiting = Arc::clone(&t);
    let policy = Arc::clone(&t);
    let exit_gate = Arc::clone(&entered);
    let policy_gate = Arc::clone(&entered);
    let exit = std::thread::spawn(move || { exit_gate.wait(); exiting.mark_done(); });
    let leave = std::thread::spawn(move || {
        policy_gate.wait();
        policy.apply_sched_update_checked(expected, normal_update())
    });
    entered.wait();
    exit.join().unwrap();
    assert_eq!(leave.join().unwrap(), crate::SchedUpdateResult::Applied);

    let observed = crate::deadline::bw::DL_BW.total_bw();
    assert_eq!(observed, baseline + p.bw,
        "the unrelated reservation must survive two concurrent leave paths");
    crate::deadline::bw::DL_BW.release(p.bw);
    assert_eq!(crate::deadline::bw::DL_BW.total_bw(), baseline);
    assert_eq!(t.sched.dl.bw(), 0);
}

fn deadline_update(p: DlParams) -> crate::SchedUpdate {
    crate::SchedUpdate {
        class: SchedClass::Deadline, policy: crate::sched_enc::SCHED_DEADLINE,
        clamp: crate::SchedUclamp::new(0, crate::sched_enc::UCLAMP_CAPACITY_SCALE, 0).unwrap(),
        reset_on_fork: false, nice: None, fair_slice: None,
        reload_rt_timeslice: false, clear_rt_timeout: false, deadline: Some(p),
    }
}

fn normal_update() -> crate::SchedUpdate {
    crate::SchedUpdate {
        class: SchedClass::Normal { weight: 1024 }, policy: crate::sched_enc::SCHED_NORMAL,
        clamp: crate::SchedUclamp::new(0, crate::sched_enc::UCLAMP_CAPACITY_SCALE, 0).unwrap(),
        reset_on_fork: false, nice: Some(0), fair_slice: Some(0),
        reload_rt_timeslice: false, clear_rt_timeout: true, deadline: None,
    }
}

fn booked_task(tid: u32, p: &DlParams) -> (Arc<Task>, u64) {
    let baseline = crate::deadline::bw::DL_BW.total_bw();
    let cap = crate::deadline::bw::capacity_of(64);
    crate::deadline::bw::DL_BW.admit(cap, true, false, 0, p.bw, false)
        .expect("task reservation fits");
    crate::deadline::bw::DL_BW.admit(cap, true, false, 0, p.bw, false)
        .expect("control reservation fits");
    let t = Arc::new(Task::new(tid, "dl", SchedClass::Deadline));
    t.set_state(TaskState::Sleeping);
    clock::set_now_ns(0);
    live::enter_class(&t, p);
    (t, baseline)
}

type ReleaseGate = Arc<(Mutex<bool>, Condvar)>;

fn race_gate() -> (std::sync::mpsc::Sender<()>, Receiver<()>, ReleaseGate) {
    let (entered_tx, entered_rx) = mpsc::channel();
    (entered_tx, entered_rx, Arc::new((Mutex::new(false), Condvar::new())))
}

fn release_gate(gate: &ReleaseGate) {
    let (lock, cv) = &**gate;
    *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
    cv.notify_all();
}

fn await_gate_or_join<T>(entered: &Receiver<()>, release: &ReleaseGate,
                         worker: &std::thread::JoinHandle<T>) {
    if entered.recv_timeout(std::time::Duration::from_secs(2)).is_ok() { return; }
    release_gate(release);
    for _ in 0..10_000 {
        if worker.is_finished() { break; }
        std::thread::yield_now();
    }
    assert!(worker.is_finished(), "deadline race worker remained live after timeout release");
    panic!("deadline race worker exited before reaching its gate");
}

#[test]
fn exit_winning_task_pi_prevents_a_concurrent_reset_from_rebooking() {
    let _g = dl_lock();
    let old = DlParams::from_request(2 * MS, 10 * MS, 10 * MS, 0);
    let new = DlParams::from_request(3 * MS, 10 * MS, 10 * MS, 0);
    let (t, baseline) = booked_task(82, &old);
    clock::set_now_ns(1);
    let expected = t.sched_policy_generation();
    let (entered_tx, entered, release) = race_gate();
    live::set_leave_claim_gate(Some((&t, entered_tx, Arc::clone(&release))));
    let _reset = LeaveBarrierReset;

    let exiting = Arc::clone(&t);
    let exit = std::thread::spawn(move || exiting.mark_done());
    await_gate_or_join(&entered, &release, &exit);
    let changing = Arc::clone(&t);
    let update = std::thread::spawn(move ||
        changing.apply_sched_update_checked(expected, deadline_update(new)));
    release_gate(&release);
    exit.join().unwrap();
    assert_eq!(update.join().unwrap(), crate::SchedUpdateResult::Applied);
    assert_eq!(t.state(), TaskState::Zombie);
    assert_eq!(t.sched.dl.bw(), 0);
    assert_eq!(crate::deadline::bw::DL_BW.total_bw(), baseline + old.bw);
    crate::deadline::bw::DL_BW.release(old.bw);
}

#[test]
fn reset_winning_task_pi_is_fully_released_by_concurrent_exit() {
    let _g = dl_lock();
    let old = DlParams::from_request(2 * MS, 10 * MS, 10 * MS, 0);
    let new = DlParams::from_request(3 * MS, 10 * MS, 10 * MS, 0);
    let (t, baseline) = booked_task(83, &old);
    let expected = t.sched_policy_generation();
    let (entered_tx, entered, release) = race_gate();
    live::set_reset_gate(Some((&t, entered_tx, Arc::clone(&release))));
    let _reset = LeaveBarrierReset;

    let changing = Arc::clone(&t);
    let update = std::thread::spawn(move ||
        changing.apply_sched_update_checked(expected, deadline_update(new)));
    await_gate_or_join(&entered, &release, &update);
    let exiting = Arc::clone(&t);
    clock::set_now_ns(1);
    let exit = std::thread::spawn(move || exiting.mark_done());
    release_gate(&release);
    assert_eq!(update.join().unwrap(), crate::SchedUpdateResult::Applied);
    exit.join().unwrap();
    assert_eq!(t.state(), TaskState::Zombie);
    assert_eq!(t.sched.dl.bw(), new.bw);
    assert_eq!(crate::deadline::bw::DL_BW.total_bw(), baseline + old.bw + new.bw,
        "exit keeps the winning reset generation until zero lag");
    live::expire_throttled(t.sched.dl.inactive_at());
    assert_eq!(t.sched.dl.bw(), 0);
    assert_eq!(crate::deadline::bw::DL_BW.total_bw(), baseline + old.bw);
    crate::deadline::bw::DL_BW.release(old.bw);
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
    assert_eq!(t.sched.dl.abs_deadline(), 9 * MS + 500_000 + 10 * MS);
    assert_eq!(t.sched.dl.sched().runtime, 2 * MS as i64);
}

#[test]
fn a_deadline_task_confined_below_the_span_is_refused() {
    let t = dl_task(1, MS, 10 * MS, 10 * MS);
    let span = crate::deadline::span();
    assert!(!live::confined_below_span(&t, span));
    assert!(!live::confined_below_span(&t, cpu::CpuMask::all()));
    let mut narrower = span;
    narrower.remove(0);
    assert!(live::confined_below_span(&t, narrower));
    // A fair task is never subject to the rule.
    assert!(!live::confined_below_span(&fair_task(2), cpu::CpuMask::empty()));
}
