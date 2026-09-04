use alloc::sync::Arc;

use crate::deadline::{self, Charged, DlParams, DlSched};
use crate::live::pi_boost;
use crate::{SchedClass, SchedPolicy, Task, TaskState};

const NOW: u64 = 10_000;

fn deadline_task(tid: u32, runtime: u64, relative: u64, absolute: u64) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "deadline", SchedClass::Deadline));
    let params = DlParams::from_request(runtime, relative, relative, 0);
    task.sched.dl.store_entity(&params, &DlSched { runtime: runtime as i64,
        deadline: absolute, throttled: false, yielded: false, overrun: false });
    task.set_state(TaskState::Sleeping);
    task
}

fn fair_owner(tid: u32) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "owner", SchedClass::Normal { weight: 1024 }));
    task.set_state(TaskState::Sleeping);
    task
}

fn rt_owner(tid: u32) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "rt-owner",
        SchedClass::Rt { prio: 70, policy: SchedPolicy::Fifo }));
    task.set_state(TaskState::Sleeping);
    task
}

#[test]
fn fair_owner_borrows_parameters_but_owns_runtime_and_absolute_deadline() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    deadline::clock::set_now_ns(NOW);
    let owner = fair_owner(0xD100);
    let donor = deadline_task(0xD101, 400, 2_000, NOW + 500);
    let donor_before = donor.sched.dl.snapshot();

    pi_boost::apply_boost(&owner, Some(Arc::clone(&donor)));

    assert_eq!(owner.effective_dl_params(), donor_before.0);
    assert_eq!(owner.sched.dl.sched(), DlSched { runtime: 400,
        deadline: 2_000, throttled: false, yielded: false, overrun: false });
    assert_eq!(donor.sched.dl.snapshot(), donor_before,
        "owner execution mutated the waiter's deadline entity");
}

#[test]
fn rt_owner_borrows_parameters_but_keeps_a_private_deadline_entity() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    deadline::clock::set_now_ns(NOW);
    let owner = rt_owner(0xD10C);
    let donor = deadline_task(0xD10D, 175, 1_250, NOW + 400);
    let donor_before = donor.sched.dl.snapshot();

    pi_boost::apply_boost(&owner, Some(Arc::clone(&donor)));

    assert_eq!(owner.sched_class(), SchedClass::Deadline);
    assert_eq!(owner.effective_dl_params(), donor_before.0);
    assert_eq!(owner.sched.dl.sched(), DlSched { runtime: 175,
        deadline: 1_250, throttled: false, yielded: false, overrun: false });
    assert_eq!(donor.sched.dl.snapshot(), donor_before);
}

#[test]
fn borrowed_budget_exhaustion_replenishes_owner_without_parking_it() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    deadline::clock::set_now_ns(NOW);
    let owner = fair_owner(0xD102);
    let donor = deadline_task(0xD103, 100, 1_000, NOW + 200);
    pi_boost::apply_boost(&owner, Some(donor));
    owner.sched.dl.set_exec_start(NOW);

    assert_eq!(deadline::live::update_curr_dl(&owner, NOW + 100), Charged::Throttle);
    assert_eq!(owner.sched.dl.sched(), DlSched { runtime: 100,
        deadline: NOW + 1_100, throttled: false, yielded: false, overrun: false });
    assert!(deadline::live::on_requeue(&owner));
    assert_eq!(owner.sched.dl.replenish_at(), 0,
        "borrowed CBS exhaustion armed a replenishment timer");
}

#[test]
fn deadline_boost_cancels_a_stale_owner_replenishment() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    deadline::replenish::clear_for_tests();
    deadline::clock::set_now_ns(NOW);
    let owner = fair_owner(0xD104);
    owner.sched.dl.store_sched(&DlSched { runtime: -20, deadline: NOW + 500,
        throttled: true, yielded: false, overrun: false });
    deadline::replenish::arm(&owner, NOW + 500);
    let donor = deadline_task(0xD105, 80, 700, NOW + 300);

    pi_boost::apply_boost(&owner, Some(donor));

    assert_eq!(owner.sched.dl.replenish_at(), 0);
    assert!(!owner.sched.dl.is_throttled());
    assert!(owner.sched.dl.sched().runtime > 0);
    deadline::replenish::clear_for_tests();
}

#[test]
fn chained_deadline_pi_propagates_the_effective_reservation() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    deadline::clock::set_now_ns(NOW);
    let first_owner = fair_owner(0xD106);
    let second_owner = fair_owner(0xD107);
    let waiter = deadline_task(0xD108, 250, 1_500, NOW + 100);

    pi_boost::apply_boost(&second_owner, Some(Arc::clone(&waiter)));
    pi_boost::apply_boost(&first_owner, Some(Arc::clone(&second_owner)));

    assert_eq!(first_owner.effective_dl_params(), waiter.sched.dl.params());
    assert_eq!(second_owner.effective_dl_params(), waiter.sched.dl.params());
    assert_eq!(first_owner.sched.dl.sched().runtime, 250);
    assert_eq!(second_owner.sched.dl.sched().runtime, 250);
    assert_ne!(first_owner.effective_dl_deadline(), waiter.effective_dl_deadline(),
        "positive control requires owner-local and waiter deadlines to differ");
}

#[test]
fn changing_waiters_restarts_a_fair_owners_entity_from_new_parameters() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    let owner = fair_owner(0xD109);
    let first = deadline_task(0xD10A, 100, 1_000, 400);
    let second = deadline_task(0xD10B, 300, 2_000, 200);
    pi_boost::apply_boost(&owner, Some(first));

    deadline::live::replenish_pi(&owner, 500);
    let second_key = pi_boost::donor_key(&second);
    pi_boost::apply_boost_keyed(&owner, Some((Arc::clone(&second), second_key)));

    assert_eq!(owner.effective_dl_params(), second.sched.dl.params());
    assert_eq!(owner.sched.dl.sched(), DlSched { runtime: 300, deadline: 2_000,
        throttled: false, yielded: false, overrun: false });
}

#[test]
fn reservation_change_rekeys_pi_even_when_absolute_deadline_is_unchanged() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    let waiter = deadline_task(0xD10E, 100, 1_000, 500);
    let before = pi_boost::donor_key(&waiter);
    let changed = DlParams::from_request(300, 1_000, 1_000, 0);

    waiter.sched.dl.set_params(&changed);
    let after = pi_boost::donor_key(&waiter);

    assert_eq!(after.deadline, before.deadline);
    assert_ne!(after, before, "reservation changes must invalidate a PI waiter key");
}

#[test]
fn zero_parameter_positive_control_reproduces_the_old_immediate_throttle() {
    let mut state = DlSched::default();
    assert_eq!(deadline::cbs::charge(&DlParams::default(), &mut state, 1), Charged::Throttle);
}
