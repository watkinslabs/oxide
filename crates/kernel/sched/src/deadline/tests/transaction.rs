use crate::deadline::{bw, clock, inactive, DlParams, DlSched};
use crate::{SchedClass, SchedUpdate, SchedUpdateResult, SchedUclamp, Task};

const MS: u64 = 1_000_000;

fn update(p: DlParams) -> SchedUpdate {
    SchedUpdate { class: SchedClass::Deadline, policy: crate::sched_enc::SCHED_DEADLINE,
        clamp: SchedUclamp::new(0, crate::sched_enc::UCLAMP_CAPACITY_SCALE, 0).unwrap(),
        reset_on_fork: false, nice: None, fair_slice: None,
        reload_rt_timeslice: false, clear_rt_timeout: false, deadline: Some(p) }
}

struct Global;
impl Global {
    fn claim() -> (Self, std::sync::MutexGuard<'static, ()>) {
        let guard = crate::tests::common::hosted_global_test_lock();
        inactive::clear_for_tests();
        crate::deadline::replenish::clear_for_tests();
        bw::init_default();
        bw::DL_BW.release(bw::DL_BW.total_bw());
        clock::set_now_ns(0);
        (Self, guard)
    }
}
impl Drop for Global {
    fn drop(&mut self) {
        inactive::clear_for_tests();
        crate::deadline::replenish::clear_for_tests();
        bw::DL_BW.release(bw::DL_BW.total_bw());
    }
}

#[test]
fn same_policy_parameter_update_preserves_the_live_cbs_instance() {
    let (_global, _guard) = Global::claim();
    let old = DlParams::from_request(4 * MS, 20 * MS, 20 * MS, 0);
    let new = DlParams::from_request(6 * MS, 30 * MS, 30 * MS, 0);
    let task = Task::new(700, "dl-update", SchedClass::Normal { weight: 1024 });
    assert_eq!(task.apply_sched_update_checked(task.sched_policy_generation(), update(old)),
        SchedUpdateResult::Applied);
    let live_before = DlSched { runtime: 2 * MS as i64, deadline: 20 * MS,
        throttled: false, yielded: false, overrun: false };
    task.sched.dl.store_sched(&live_before);

    assert_eq!(task.apply_sched_update_checked(task.sched_policy_generation(), update(new)),
        SchedUpdateResult::Applied);
    assert_eq!(task.sched_deadline_params(), new, "static reservation was not replaced");
    assert_eq!(task.sched_deadline_state(), live_before,
        "setattr minted runtime or replaced the current absolute deadline");
}

#[test]
fn resetting_the_instance_is_a_positive_control_for_budget_minting() {
    let old_live = DlSched { runtime: 2 * MS as i64, deadline: 20 * MS,
        throttled: false, yielded: false, overrun: false };
    let new = DlParams::from_request(6 * MS, 30 * MS, 30 * MS, 0);
    let mut wrong = old_live;
    crate::deadline::cbs::replenish_new_period(&new, &mut wrong, 0);
    assert_eq!(wrong.runtime, 6 * MS as i64);
    assert_ne!(wrong, old_live, "positive control no longer mints a fresh CBS instance");
}

#[test]
fn zero_lag_uses_signed_runtime_and_wrapping_time() {
    let p = DlParams::from_request(2 * MS, 10 * MS, 10 * MS, 0);
    let overrun = DlSched { runtime: -(MS as i64), deadline: 10 * MS,
        throttled: true, yielded: false, overrun: true };
    assert_eq!(inactive::zero_lag(&p, &overrun), 15 * MS,
        "overrun debt must retain bandwidth beyond the absolute deadline");

    let wrapped = DlSched { runtime: MS as i64, deadline: 2,
        throttled: false, yielded: false, overrun: false };
    assert_eq!(inactive::zero_lag(&p, &wrapped), 2u64.wrapping_sub(5 * MS));
}

#[test]
fn clamped_and_saturating_zero_lag_are_positive_controls() {
    let deadline = 10 * MS;
    let clamped_negative = deadline.saturating_sub(0);
    assert_eq!(clamped_negative, deadline,
        "control demonstrates that clamping loses overrun retention");
    let saturating_wrap = 2u64.saturating_sub(5 * MS);
    assert_eq!(saturating_wrap, 0,
        "control demonstrates that saturation destroys wrapped clock order");
}
