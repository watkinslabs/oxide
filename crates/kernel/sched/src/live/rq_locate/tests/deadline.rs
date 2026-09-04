use super::*;
use crate::SchedClass;

#[test]
fn key_change_physically_reorders_two_task_edf_tree() {
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let changed = deadline_task(33, 10_000_000);
    let peer = deadline_task(34, 20_000_000);
    {
        let rq = cpus.get(REMOTE_CPU).unwrap();
        let mut inner = rq.inner.lock();
        changed.cpu.store(REMOTE_CPU as u16, Ordering::Release);
        changed.on_rq.store(true, Ordering::Release);
        inner.restore_sched_change(
            Arc::clone(&changed),
            crate::sched_enc::requeue::RequeuePos::Head,
        );
        peer.cpu.store(REMOTE_CPU as u16, Ordering::Release);
        peer.on_rq.store(true, Ordering::Release);
        inner.restore_sched_change(peer, crate::sched_enc::requeue::RequeuePos::Head);
    }
    let StableTaskGuard::Owned(lock) = task_rq_lock_with(&|c| cpus.get(c), &changed)
    else {
        panic!("queued DL task lost rq ownership")
    };
    let change = SchedChange::from_lock_mode(lock, &changed, 0, true);
    let mut state = changed.sched.dl.sched();
    state.deadline = 30_000_000;
    changed.sched.dl.store_sched(&state);
    drop(change);

    let mut inner = cpus.get(REMOTE_CPU).unwrap().inner.lock();
    assert_eq!(inner.pick_next_task().tid, 34);
    assert_eq!(inner.pick_next_task().tid, 33);
}

#[test]
fn same_policy_update_preserves_partial_cbs_and_edf_position() {
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let changed = deadline_task(37, 10_000_000);
    let peer = deadline_task(38, 20_000_000);
    let partial = crate::deadline::DlSched {
        runtime: 400_000,
        deadline: 10_000_000,
        throttled: false,
        yielded: false,
        overrun: false,
    };
    changed.sched.dl.store_sched(&partial);
    {
        let rq = cpus.get(REMOTE_CPU).unwrap();
        let mut inner = rq.inner.lock();
        changed.cpu.store(REMOTE_CPU as u16, Ordering::Release);
        changed.on_rq.store(true, Ordering::Release);
        inner.restore_sched_change(
            Arc::clone(&changed),
            crate::sched_enc::requeue::RequeuePos::Head,
        );
        peer.cpu.store(REMOTE_CPU as u16, Ordering::Release);
        peer.on_rq.store(true, Ordering::Release);
        inner.restore_sched_change(peer, crate::sched_enc::requeue::RequeuePos::Head);
    }

    let StableTaskGuard::Owned(lock) = task_rq_lock_with(&|c| cpus.get(c), &changed)
    else {
        panic!("queued DL task lost rq ownership")
    };
    let change = SchedChange::from_lock_mode(lock, &changed, 0, true);
    let replacement =
        crate::deadline::DlParams::from_request(2_000_000, 30_000_000, 30_000_000, 0);
    crate::deadline::live::reset_params(&changed, &replacement);
    drop(change);

    assert_eq!(
        changed.sched.dl.sched(),
        partial,
        "same-policy setattr minted budget or changed the absolute deadline"
    );
    assert_eq!(changed.sched.dl.params(), replacement);
    let mut inner = cpus.get(REMOTE_CPU).unwrap().inner.lock();
    assert_eq!(
        inner.pick_next_task().tid,
        changed.tid,
        "unchanged dynamic key lost its EDF position"
    );
    assert_eq!(inner.pick_next_task().tid, 38);
}

#[test]
fn running_demotion_requests_a_reschedule() {
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let current = deadline_task(35, 10_000_000);
    current.cpu.store(REMOTE_CPU as u16, Ordering::Release);
    current.on_cpu.store(true, Ordering::Release);
    current.on_rq.store(true, Ordering::Release);
    let rq = cpus.get(REMOTE_CPU).unwrap();
    // SAFETY: this hosted test exclusively owns the local runqueue.
    let _idle = unsafe { rq.swap_current(Arc::clone(&current)) };
    let waiting = deadline_task(42, 20_000_000);
    enqueue_on(&cpus, REMOTE_CPU, waiting);
    let StableTaskGuard::Owned(lock) = task_rq_lock_with(&|c| cpus.get(c), &current)
    else {
        panic!("running DL task lost rq ownership")
    };
    let change = SchedChange::from_lock_mode(lock, &current, 0, true);
    let mut state = current.sched.dl.sched();
    state.deadline = 30_000_000;
    current.sched.dl.store_sched(&state);
    drop(change);
    assert!(current.need_resched.load(Ordering::Acquire));
}

#[test]
fn terminal_deadline_release_waits_for_final_schedule_out_charge() {
    let _global = crate::tests::common::hosted_global_test_lock();
    crate::deadline::inactive::clear_for_tests();
    crate::deadline::bw::init_default();
    crate::deadline::bw::DL_BW.release(crate::deadline::bw::DL_BW.total_bw());
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let current = deadline_task(36, 20_000_000);
    let params =
        crate::deadline::DlParams::from_request(5_000_000, 20_000_000, 20_000_000, 0);
    current.sched.dl.set_params(&params);
    current.sched.dl.store_sched(&crate::deadline::DlSched {
        runtime: 5_000_000,
        deadline: 20_000_000,
        throttled: false,
        yielded: false,
        overrun: false,
    });
    crate::deadline::bw::DL_BW.admit(crate::deadline::bw::capacity_of(64),
        true, false, 0, params.bw, false).expect("fixture reservation fits");
    current.sched.dl.set_exec_start(0);
    current.cpu.store(REMOTE_CPU as u16, Ordering::Release);
    current.on_cpu.store(true, Ordering::Release);
    current.on_rq.store(true, Ordering::Release);
    let rq = cpus.get(REMOTE_CPU).unwrap();
    // SAFETY: this hosted test exclusively owns the local runqueue.
    let _idle = unsafe { rq.swap_current(Arc::clone(&current)) };
    terminal_with(&|c| cpus.get(c), &current, 3_000_000);
    assert_eq!(current.sched.dl.sched().runtime, 5_000_000,
        "terminal publication charged a task that was still executing");
    assert_eq!(current.sched.dl.inactive_at(), 0,
        "terminal publication released bandwidth before final schedule-out");
    let _ = crate::deadline::live::update_curr_dl(&current, 5_000_000);
    finish_terminal_deadline(&current);
    assert_eq!(current.sched.dl.sched().runtime, 0);
    assert_eq!(current.sched.dl.inactive_at(), 20_000_000,
        "zero lag did not include exit-tail execution");
    crate::deadline::inactive::expire(20_000_000);
    assert_eq!(crate::deadline::bw::DL_BW.total_bw(), 0);
}

#[test]
fn pi_deadline_donation_rekeys_a_queued_owner_by_effective_deadline() {
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let owner = deadline_task(39, 30_000_000);
    let peer = deadline_task(40, 20_000_000);
    let donor = deadline_task(41, 10_000_000);
    donor.set_state(crate::TaskState::Sleeping);
    {
        let rq = cpus.get(REMOTE_CPU).unwrap();
        let mut inner = rq.inner.lock();
        for task in [Arc::clone(&owner), Arc::clone(&peer)] {
            task.cpu.store(REMOTE_CPU as u16, Ordering::Release);
            task.on_rq.store(true, Ordering::Release);
            inner.restore_sched_change(task, crate::sched_enc::requeue::RequeuePos::Head);
        }
    }

    let StableTaskGuard::Owned(lock) = task_rq_lock_with(&|c| cpus.get(c), &owner)
    else { panic!("queued owner lost rq ownership") };
    let change = SchedChange::from_lock(lock, &owner, 0);
    owner.set_pi_top_task_unlocked(Some((&donor, donor.pi_donor_key_unlocked())));
    drop(change);

    let mut inner = cpus.get(REMOTE_CPU).unwrap().inner.lock();
    assert_eq!(inner.pick_next_task().tid, owner.tid,
        "ready key ignored the donated effective deadline");
    assert_eq!(inner.pick_next_task().tid, peer.tid);
}

#[test]
fn queued_deadline_leave_never_takes_task_list_below_rq_lock() {
    let _global = crate::tests::common::hosted_global_test_lock();
    crate::deadline::inactive::clear_for_tests();
    crate::deadline::bw::init_default();
    crate::deadline::bw::DL_BW.release(crate::deadline::bw::DL_BW.total_bw());
    crate::deadline::clock::set_now_ns(0);
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let task = deadline_task(43, 20_000_000);
    let params = task.sched.dl.params();
    crate::deadline::bw::DL_BW.admit(crate::deadline::bw::capacity_of(64),
        true, false, 0, params.bw, false).expect("fixture reservation fits");
    task.sched.dl.store_sched(&crate::deadline::DlSched {
        runtime: 500_000, deadline: 20_000_000, throttled: false,
        yielded: false, overrun: false,
    });
    enqueue_on(&cpus, REMOTE_CPU, Arc::clone(&task));
    let update = crate::SchedUpdate {
        class: SchedClass::Normal { weight: 1024 },
        policy: crate::sched_enc::SCHED_NORMAL,
        clamp: crate::SchedUclamp::new(0,
            crate::sched_enc::UCLAMP_CAPACITY_SCALE, 0).unwrap(),
        reset_on_fork: false, nice: None, fair_slice: None,
        reload_rt_timeslice: false, clear_rt_timeout: true, deadline: None,
    };

    assert_eq!(crate::live::runqueue::apply_update_with(&|c| cpus.get(c), &task,
        task.sched_policy_generation(), update), crate::SchedUpdateResult::Applied);
    assert!(matches!(task.sched_class(), SchedClass::Normal { .. }));
    assert!(task.sched.dl.inactive_at() != 0,
        "fixture did not exercise inactive-timer arming under rq lock");
    crate::deadline::inactive::expire(task.sched.dl.inactive_at());
}
