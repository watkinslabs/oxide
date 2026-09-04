use crate::deadline::{bw, clock, inactive, live, DlParams, DlSched, FLAG_SUGOV};
use crate::{SchedClass, SchedUpdate, SchedUpdateResult, SchedUclamp, Task, TaskState};

const MS: u64 = 1_000_000;

struct Global;
impl Global {
    fn new() -> (Global, std::sync::MutexGuard<'static, ()>) {
        let guard = crate::tests::common::hosted_global_test_lock();
        inactive::clear_for_tests();
        crate::deadline::replenish::clear_for_tests();
        bw::init_default();
        bw::DL_BW.release(bw::DL_BW.total_bw());
        clock::set_now_ns(0);
        (Global, guard)
    }
}
impl Drop for Global {
    fn drop(&mut self) {
        inactive::clear_for_tests();
        crate::deadline::replenish::clear_for_tests();
        bw::DL_BW.release(bw::DL_BW.total_bw());
    }
}

fn clamp() -> SchedUclamp {
    SchedUclamp::new(0, crate::sched_enc::UCLAMP_CAPACITY_SCALE, 0).unwrap()
}

fn update(policy: u32, params: Option<DlParams>) -> SchedUpdate {
    let class = if policy == crate::sched_enc::SCHED_DEADLINE {
        SchedClass::Deadline
    } else {
        SchedClass::Normal { weight: 1024 }
    };
    SchedUpdate { class, policy, clamp: clamp(), reset_on_fork: false, nice: None,
        fair_slice: None, reload_rt_timeslice: false, clear_rt_timeout: true,
        deadline: params }
}

fn commit(t: &Task, update: SchedUpdate) -> SchedUpdateResult {
    t.apply_sched_update_checked(t.sched_policy_generation(), update)
}

fn ordinary(runtime: u64) -> DlParams {
    DlParams::from_request(runtime, 10 * MS, 10 * MS, 0)
}

fn special() -> DlParams {
    DlParams::from_request(MS, 10 * MS, 10 * MS, FLAG_SUGOV)
}

fn set_zero_lag_five_ms(t: &Task, p: &DlParams) {
    t.sched.dl.store_sched(&DlSched { runtime: (p.runtime / 2) as i64, deadline: 10 * MS,
        throttled: false, yielded: false, overrun: false });
}

#[test]
fn zero_lag_is_deadline_minus_remaining_runtime_scaled_by_period() {
    let p = ordinary(2 * MS);
    let s = DlSched { runtime: MS as i64, deadline: 10 * MS,
        throttled: false, yielded: false, overrun: false };
    assert_eq!(inactive::zero_lag(&p, &s), 5 * MS);
}

#[test]
fn policy_leave_retains_before_and_releases_at_zero_lag() {
    let (_global, _guard) = Global::new();
    let t = Task::new(1, "zero-lag-leave", SchedClass::Normal { weight: 1024 });
    let p = ordinary(2 * MS);
    assert_eq!(commit(&t, update(crate::sched_enc::SCHED_DEADLINE, Some(p))),
               SchedUpdateResult::Applied);
    set_zero_lag_five_ms(&t, &p);
    assert_eq!(commit(&t, update(crate::sched_enc::SCHED_NORMAL, None)),
               SchedUpdateResult::Applied);
    assert_eq!(t.sched.dl.inactive_at(), 5 * MS);
    assert_eq!(bw::DL_BW.total_bw(), p.bw);
    live::expire_throttled(5 * MS - 1);
    assert_eq!(bw::DL_BW.total_bw(), p.bw, "booking remains before zero lag");
    live::expire_throttled(5 * MS);
    assert_eq!(bw::DL_BW.total_bw(), 0, "timer releases at zero lag");
    assert_eq!(t.sched_deadline_params(), DlParams::default());
}

#[test]
fn equality_at_zero_lag_is_due_now_and_never_arms() {
    let (_global, _guard) = Global::new();
    let t = Task::new(40, "zero-lag-equal", SchedClass::Normal { weight: 1024 });
    let p = ordinary(2 * MS);
    assert_eq!(commit(&t, update(crate::sched_enc::SCHED_DEADLINE, Some(p))),
               SchedUpdateResult::Applied);
    set_zero_lag_five_ms(&t, &p);
    clock::set_now_ns(5 * MS);
    assert_eq!(commit(&t, update(crate::sched_enc::SCHED_NORMAL, None)),
               SchedUpdateResult::Applied);
    assert_eq!(t.sched.dl.inactive_at(), 0, "equality incorrectly armed a timer");
    assert_eq!(bw::DL_BW.total_bw(), 0, "due-now booking was not released");
}

#[test]
fn leave_and_expiry_follow_wrapping_deadline_order() {
    let (_global, _guard) = Global::new();
    let t = Task::new(41, "zero-lag-wrap", SchedClass::Normal { weight: 1024 });
    let p = ordinary(2 * MS);
    assert_eq!(commit(&t, update(crate::sched_enc::SCHED_DEADLINE, Some(p))),
               SchedUpdateResult::Applied);
    let live_state = DlSched { runtime: MS as i64, deadline: 2,
        throttled: false, yielded: false, overrun: false };
    let at = inactive::zero_lag(&p, &live_state);
    t.sched.dl.store_sched(&live_state);
    clock::set_now_ns(at.wrapping_sub(1));
    assert_eq!(commit(&t, update(crate::sched_enc::SCHED_NORMAL, None)),
               SchedUpdateResult::Applied);
    assert_eq!(t.sched.dl.inactive_at(), at, "wrapped future was treated as past");
    live::expire_throttled(at.wrapping_sub(1));
    assert_eq!(bw::DL_BW.total_bw(), p.bw);
    live::expire_throttled(at);
    assert_eq!(bw::DL_BW.total_bw(), 0, "wrapped equality was not treated as due");
}

#[test]
fn negative_runtime_arms_beyond_the_absolute_deadline() {
    let (_global, _guard) = Global::new();
    let t = Task::new(42, "zero-lag-overrun", SchedClass::Normal { weight: 1024 });
    let p = ordinary(2 * MS);
    assert_eq!(commit(&t, update(crate::sched_enc::SCHED_DEADLINE, Some(p))),
               SchedUpdateResult::Applied);
    t.sched.dl.store_sched(&DlSched { runtime: -(MS as i64), deadline: 10 * MS,
        throttled: true, yielded: false, overrun: true });
    clock::set_now_ns(11 * MS);
    assert_eq!(commit(&t, update(crate::sched_enc::SCHED_NORMAL, None)),
               SchedUpdateResult::Applied);
    assert_eq!(t.sched.dl.inactive_at(), 15 * MS,
        "signed overrun debt did not extend zero lag beyond deadline");
    live::expire_throttled(15 * MS);
}

#[test]
fn exit_retains_the_booking_until_its_inactive_timer_fires() {
    let (_global, _guard) = Global::new();
    let t = Task::new(2, "zero-lag-exit", SchedClass::Normal { weight: 1024 });
    let p = ordinary(2 * MS);
    assert_eq!(commit(&t, update(crate::sched_enc::SCHED_DEADLINE, Some(p))),
               SchedUpdateResult::Applied);
    set_zero_lag_five_ms(&t, &p);
    t.set_state(TaskState::Sleeping);
    t.mark_done();
    assert_eq!(t.state(), TaskState::Zombie);
    assert_eq!(bw::DL_BW.total_bw(), p.bw);
    live::expire_throttled(5 * MS - 1);
    assert_eq!(bw::DL_BW.total_bw(), p.bw);
    live::expire_throttled(5 * MS);
    assert_eq!(bw::DL_BW.total_bw(), 0);
    assert_eq!(t.sched_deadline_params(), DlParams::default());
}

#[test]
fn retained_booking_prevents_policy_churn_overcommit() {
    let (_global, _guard) = Global::new();
    let a = Task::new(3, "leaver", SchedClass::Normal { weight: 1024 });
    let b = Task::new(4, "entrant", SchedClass::Normal { weight: 1024 });
    let sixty = ordinary(6 * MS);
    assert_eq!(commit(&a, update(crate::sched_enc::SCHED_DEADLINE, Some(sixty))),
               SchedUpdateResult::Applied);
    set_zero_lag_five_ms(&a, &sixty);
    assert_eq!(commit(&a, update(crate::sched_enc::SCHED_NORMAL, None)),
               SchedUpdateResult::Applied);
    assert_eq!(commit(&b, update(crate::sched_enc::SCHED_DEADLINE, Some(sixty))),
               SchedUpdateResult::DeadlineBusy);
    live::expire_throttled(5 * MS);
    assert_eq!(commit(&b, update(crate::sched_enc::SCHED_DEADLINE, Some(sixty))),
               SchedUpdateResult::Applied);
}

#[test]
fn reentry_replaces_the_pending_booking_instead_of_adding_to_it() {
    let (_global, _guard) = Global::new();
    let t = Task::new(5, "reenter", SchedClass::Normal { weight: 1024 });
    let twenty = ordinary(2 * MS);
    let thirty = ordinary(3 * MS);
    assert_eq!(commit(&t, update(crate::sched_enc::SCHED_DEADLINE, Some(twenty))),
               SchedUpdateResult::Applied);
    set_zero_lag_five_ms(&t, &twenty);
    assert_eq!(commit(&t, update(crate::sched_enc::SCHED_NORMAL, None)),
               SchedUpdateResult::Applied);
    clock::set_now_ns(MS);
    assert_eq!(commit(&t, update(crate::sched_enc::SCHED_DEADLINE, Some(thirty))),
               SchedUpdateResult::Applied);
    assert_eq!(bw::DL_BW.total_bw(), thirty.bw, "20% was replaced, never added");
    assert_eq!(t.sched.dl.inactive_at(), 0);
    assert_eq!(t.sched_deadline_state().deadline, 10 * MS,
        "reentry before expiry keeps the current instance");
    live::expire_throttled(5 * MS);
    assert_eq!(bw::DL_BW.total_bw(), thirty.bw, "cancelled timer cannot subtract replacement");
}

#[test]
fn sugov_remove_never_subtracts_its_fake_parameters() {
    let (_global, _guard) = Global::new();
    let ordinary_task = Task::new(6, "ordinary", SchedClass::Normal { weight: 1024 });
    let governor = Task::new(7, "sugov", SchedClass::Normal { weight: 1024 });
    let half = ordinary(5 * MS);
    assert_eq!(commit(&ordinary_task, update(crate::sched_enc::SCHED_DEADLINE, Some(half))),
               SchedUpdateResult::Applied);
    assert_eq!(commit(&governor, update(crate::sched_enc::SCHED_DEADLINE, Some(special()))),
               SchedUpdateResult::Applied);
    assert_eq!(bw::DL_BW.total_bw(), half.bw);
    assert_eq!(commit(&governor, update(crate::sched_enc::SCHED_NORMAL, None)),
               SchedUpdateResult::Applied);
    assert_eq!(bw::DL_BW.total_bw(), half.bw);
}

#[test]
fn special_to_ordinary_adds_and_ordinary_to_special_expires_only_the_ordinary_booking() {
    let (_global, _guard) = Global::new();
    let t = Task::new(8, "special-transition", SchedClass::Normal { weight: 1024 });
    let thirty = ordinary(3 * MS);
    assert_eq!(commit(&t, update(crate::sched_enc::SCHED_DEADLINE, Some(special()))),
               SchedUpdateResult::Applied);
    assert_eq!(bw::DL_BW.total_bw(), 0);
    assert_eq!(commit(&t, update(crate::sched_enc::SCHED_DEADLINE, Some(thirty))),
               SchedUpdateResult::Applied);
    assert_eq!(bw::DL_BW.total_bw(), thirty.bw);
    set_zero_lag_five_ms(&t, &thirty);
    assert_eq!(commit(&t, update(crate::sched_enc::SCHED_DEADLINE, Some(special()))),
               SchedUpdateResult::Applied);
    assert_eq!(bw::DL_BW.total_bw(), thirty.bw);
    assert!(t.sched_deadline_params().is_special());
    live::expire_throttled(5 * MS);
    assert_eq!(bw::DL_BW.total_bw(), 0);
    assert!(t.sched_deadline_params().is_special(),
        "old ordinary expiry cannot clear the installed special generation");
}

#[test]
fn immediate_release_positive_control_allows_two_live_sixty_percent_claims() {
    let ledger = bw::DlBw::new();
    let sixty = ordinary(6 * MS).bw;
    ledger.admit(bw::capacity_of(1), true, false, 0, sixty, false).unwrap();
    ledger.release(sixty);
    ledger.admit(bw::capacity_of(1), true, false, 0, sixty, false).unwrap();
    assert_eq!(ledger.total_bw(), sixty,
        "control forgot the first task still contributes before zero lag");
}

#[test]
fn policy_only_positive_control_adds_pending_twenty_to_new_thirty() {
    let twenty = ordinary(2 * MS).bw;
    let thirty = ordinary(3 * MS).bw;
    let change = bw::plan(crate::deadline::BW_UNIT, bw::capacity_of(1), twenty,
                          true, false, 0, thirty, false).unwrap();
    assert_eq!(change, bw::BwChange::Add { new: thirty });
    let wrong = twenty + thirty;
    assert!(wrong > thirty, "control exposes policy/booked-state conflation");
}

#[test]
fn sugov_subtraction_positive_control_erases_unrelated_bandwidth() {
    let total = ordinary(5 * MS).bw;
    let fake = special().bw;
    assert!(total.saturating_sub(fake) < total,
        "control exposes subtraction of bandwidth SUGOV never booked");
}
