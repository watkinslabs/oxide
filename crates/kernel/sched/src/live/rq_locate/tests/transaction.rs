use super::*;
use alloc::{boxed::Box, sync::Arc};
use core::cell::Cell;
use crate::{SchedClass, SchedPolicy};

fn rt(prio: u8) -> SchedClass {
    SchedClass::Rt { prio, policy: SchedPolicy::Fifo }
}

fn rt_update(prio: u8) -> crate::SchedUpdate {
    crate::SchedUpdate {
        class: rt(prio), policy: crate::sched_enc::SCHED_FIFO,
        clamp: crate::SchedUclamp::new(0,
            crate::sched_enc::UCLAMP_CAPACITY_SCALE, 0).unwrap(),
        reset_on_fork: false, nice: None, fair_slice: None,
        reload_rt_timeslice: false, clear_rt_timeout: true, deadline: None,
    }
}

#[test]
fn rejected_queued_policy_update_preserves_owner_and_rt_order() {
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let peer = Arc::new(Task::new(90, "peer", rt(30)));
    let changed = Arc::new(Task::new(91, "changed", rt(30)));
    enqueue_on(&cpus, REMOTE_CPU, Arc::clone(&peer));
    enqueue_on(&cpus, REMOTE_CPU, Arc::clone(&changed));
    let current = changed.sched_policy_generation();
    let stale = (current.0, current.1.wrapping_add(1));

    assert_eq!(crate::live::runqueue::apply_update_with(
        &|cpu| cpus.get(cpu), &changed, stale, rt_update(60)),
        crate::SchedUpdateResult::Stale);

    assert_eq!(changed.sched_class(), rt(30));
    assert_eq!(changed.cpu.load(Ordering::Acquire), REMOTE_CPU as u16);
    assert!(changed.on_rq.is_queued(Ordering::Acquire));
    assert!(changed.on_class_rq.load(Ordering::Acquire));
    let mut inner = cpus.get(REMOTE_CPU).unwrap().inner.lock();
    assert_eq!(inner.nr_running(), 2);
    assert_eq!(inner.pick_next_task().tid, peer.tid,
        "a rejected transaction detached and head-restored the RT tail");
    assert_eq!(inner.pick_next_task().tid, changed.tid);
}

#[test]
fn positive_control_entering_sched_change_reorders_the_rt_tail() {
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let peer = Arc::new(Task::new(92, "peer", rt(30)));
    let changed = Arc::new(Task::new(93, "changed", rt(30)));
    enqueue_on(&cpus, REMOTE_CPU, peer);
    enqueue_on(&cpus, REMOTE_CPU, Arc::clone(&changed));

    let StableTaskGuard::Owned(lock) = task_rq_lock_with(&|cpu| cpus.get(cpu), &changed)
        else { panic!("queued task lost its owning runqueue") };
    drop(SchedChange::from_lock(lock, &changed, 0));

    let mut inner = cpus.get(REMOTE_CPU).unwrap().inner.lock();
    assert_eq!(inner.pick_next_task().tid, changed.tid,
        "positive control no longer detects an unnecessary dequeue/head restore");
}

#[test]
fn sched_change_unwind_restores_exact_queued_owner() {
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let changed = Arc::new(Task::new(94, "changed", rt(30)));
    let peer = Arc::new(Task::new(95, "peer", rt(30)));
    enqueue_on(&cpus, REMOTE_CPU, Arc::clone(&changed));
    enqueue_on(&cpus, REMOTE_CPU, Arc::clone(&peer));

    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mutate_with(&|cpu| cpus.get(cpu), &changed, |task| {
            assert!(!task.on_class_rq.load(Ordering::Acquire),
                "fixture never reached the detached transaction body");
            panic!("injected mutation failure");
        });
    }));

    assert!(failed.is_err());
    assert_eq!(changed.cpu.load(Ordering::Acquire), REMOTE_CPU as u16);
    assert!(changed.on_rq.is_queued(Ordering::Acquire));
    assert!(changed.on_class_rq.load(Ordering::Acquire));
    let mut inner = cpus.get(REMOTE_CPU).unwrap().inner.lock();
    assert_eq!(inner.nr_running(), 2, "unwind lost or duplicated a queued task");
    assert_eq!(inner.pick_next_task().tid, changed.tid);
    assert_eq!(inner.pick_next_task().tid, peer.tid);
}

fn grouped(tid: u32, group: u64, shares: u32) -> Arc<Task> {
    let task = normal_task(tid);
    task.sched.store_group_id(group);
    task.sched.store_group_shares(shares);
    task
}

struct InstalledGlobal;

impl InstalledGlobal {
    fn new() -> Self {
        let idle = Arc::new(Task::new(10_000, "idle", SchedClass::Idle));
        // SAFETY: hosted_global_test_lock serializes the sole hosted global runqueue slot.
        unsafe { crate::live::runqueue::install_global(Runqueue::new(0, idle)); }
        Self
    }
}

impl Drop for InstalledGlobal {
    fn drop(&mut self) {
        // SAFETY: the fixture owns hosted_global_test_lock until after this teardown.
        let _ = unsafe { crate::live::runqueue::uninstall_global() };
    }
}

fn enqueue_global(task: Arc<Task>) {
    let rq = crate::live::runqueue::global().unwrap();
    let mut inner = rq.inner.lock();
    assert!(inner.enqueue(task));
    rq.publish_nr_running(inner.nr_running());
}

#[test]
fn queued_group_mutation_refreshes_the_real_cfs_group_key() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    let _installed = InstalledGlobal::new();
    let changed = grouped(96, 10, 1024);
    let peer = grouped(97, 20, 512);
    enqueue_global(Arc::clone(&changed));
    enqueue_global(Arc::clone(&peer));

    crate::live::runqueue::set_group_shares(&changed, 10, 256);

    assert_eq!(changed.sched.group_shares(), 256);
    assert_eq!(changed.cpu.load(Ordering::Acquire), 0);
    assert!(changed.on_rq.is_queued(Ordering::Acquire));
    assert!(changed.on_class_rq.load(Ordering::Acquire));
    let mut inner = crate::live::runqueue::global().unwrap().inner.lock();
    assert_eq!(inner.nr_running(), 2);
    assert_eq!(inner.pick_next_task().tid, peer.tid,
        "group mutation left the parent-facing CFS key at its old shares");
    assert_eq!(inner.pick_next_task().tid, changed.tid);
}

#[test]
fn positive_control_direct_group_store_leaves_a_stale_cfs_group_key() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    let _installed = InstalledGlobal::new();
    let changed = grouped(98, 10, 1024);
    let peer = grouped(99, 20, 512);
    enqueue_global(Arc::clone(&changed));
    enqueue_global(peer);

    changed.sched.store_group_shares(256);

    let mut inner = crate::live::runqueue::global().unwrap().inner.lock();
    assert_eq!(inner.pick_next_task().tid, changed.tid,
        "positive control no longer reproduces a stale runqueue group key");
}

#[test]
fn policy_commit_after_migration_rekeys_only_the_destination_rq() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    let changed = normal_task(100);
    let peer = Arc::new(Task::new(101, "peer", rt(50)));
    enqueue_on(&cpus, CALLER_CPU, Arc::clone(&changed));
    enqueue_on(&cpus, REMOTE_CPU, Arc::clone(&peer));
    let stage = Cell::new(0u8);

    let moved = crate::live::migration::move_queued_with(
        &|cpu| cpus.get(cpu), &changed, Some(REMOTE_CPU), &|_| true,
        &mut |point, _, _| {
            use crate::live::migration::MovePoint;
            let want = match point {
                MovePoint::SourceLocked => 0,
                MovePoint::SourceDetached => 1,
                MovePoint::DestinationLocked => 2,
                MovePoint::DestinationCommitted => 3,
            };
            assert_eq!(stage.get(), want, "migration publication order changed");
            stage.set(want + 1);
        });
    assert!(matches!(moved, crate::live::migration::MoveResult::Moved {
        from: CALLER_CPU, to: REMOTE_CPU }));
    assert_eq!(stage.get(), 4);

    assert_eq!(crate::live::runqueue::apply_update_with(
        &|cpu| cpus.get(cpu), &changed, changed.sched_policy_generation(), rt_update(60)),
        crate::SchedUpdateResult::Applied);

    assert_eq!(changed.cpu.load(Ordering::Acquire), REMOTE_CPU as u16);
    assert_eq!(cpus.get(CALLER_CPU).unwrap().inner.lock().nr_running(), 0);
    let mut destination = cpus.get(REMOTE_CPU).unwrap().inner.lock();
    assert_eq!(destination.nr_running(), 2);
    assert_eq!(destination.pick_next_task().tid, changed.tid,
        "post-migration policy mutation failed to rekey the destination tree");
    assert_eq!(destination.pick_next_task().tid, peer.tid);
}

#[test]
fn pi_waiter_promotion_rekeys_real_rq_and_preempts_current() {
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let current = normal_task(102);
    current.cpu.store(REMOTE_CPU as u16, Ordering::Release);
    current.on_cpu.store(true, Ordering::Release);
    current.on_rq.store(true, Ordering::Release);
    let rq = cpus.get(REMOTE_CPU).unwrap();
    // SAFETY: this hosted test exclusively owns the isolated runqueue.
    let _idle = unsafe { rq.swap_current(Arc::clone(&current)) };
    let peer = Arc::new(Task::new(103, "peer", rt(50)));
    let owner = normal_task(104);
    enqueue_on(&cpus, REMOTE_CPU, Arc::clone(&peer));
    enqueue_on(&cpus, REMOTE_CPU, Arc::clone(&owner));
    let donor = Arc::new(Task::new(105, "donor", rt(70)));
    donor.set_state(crate::TaskState::Sleeping);
    let key = crate::pi_prio::PiDonorKey { class: rt(70), deadline: 0, special: false,
        ..crate::pi_prio::PiDonorKey::default() };
    let mut node = Box::pin(crate::pi_prio::PiTreeNode::new(&donor, key, 1, 1, 1));

    assert!(crate::live::pi_boost::update_owner_waiters_with(
        &|cpu| cpus.get(cpu), &owner, |pi| pi.insert_waiter(node.as_mut())));

    assert_eq!(owner.sched_class(), rt(70));
    assert!(owner.on_rq.is_queued(Ordering::Acquire));
    assert!(owner.on_class_rq.load(Ordering::Acquire));
    assert!(current.need_resched.load(Ordering::Acquire),
        "PI promotion above current did not request preemption");
    assert_eq!(rq.inner.lock().peek_next_task().tid, owner.tid,
        "PI promotion changed scalar priority without moving the ready node");

    assert!(crate::live::pi_boost::update_owner_waiters_with(
        &|cpu| cpus.get(cpu), &owner, |pi| pi.remove_waiter(node.as_mut())));
    assert!(matches!(owner.sched_class(), SchedClass::Normal { .. }));
    assert_eq!(rq.inner.lock().peek_next_task().tid, peer.tid,
        "PI deboost left the owner in the real-time tree");
}

#[test]
fn positive_control_effective_store_without_rekey_is_visible_in_real_rq() {
    let cpus = Cpus::new(&[REMOTE_CPU]);
    let peer = Arc::new(Task::new(106, "peer", rt(50)));
    let owner = normal_task(107);
    enqueue_on(&cpus, REMOTE_CPU, peer);
    enqueue_on(&cpus, REMOTE_CPU, Arc::clone(&owner));

    owner.sched.store_effective_class(rt(70));

    assert_eq!(cpus.get(REMOTE_CPU).unwrap().inner.lock().peek_next_task().tid, 106,
        "positive control no longer detects a scalar PI update with a stale ready node");
    owner.sched.store_effective_class(SchedClass::Normal { weight: 1024 });
}
