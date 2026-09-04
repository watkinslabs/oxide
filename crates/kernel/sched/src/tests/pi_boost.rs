// Base-class reporting for a PI-boosted task (`crate::pi_prio::{base_class,
// is_boosted}`). Lives here rather than beside the rule in `pi_prio.rs`
// because these need a real `Task`, and `pi_prio.rs` is `#[path]`-included by
// the `ipc` futex harnesses, which supply their own minimal `Task`.

use crate::pi_prio::{base_class, is_boosted};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{mpsc, Arc as StdArc};

use crate::{SchedClass, SchedPolicy, Task};
use crate::live::{pi_boost, runqueue::{self, Runqueue}};

const OWNER_TID: u32 = 0xB3320;
const IDLE_TID: u32 = 0xF3320;
const fn rt(p: u8) -> SchedClass { SchedClass::Rt { prio: p, policy: SchedPolicy::Fifo } }
const fn fair(w: u32) -> SchedClass { SchedClass::Normal { weight: w } }

static CALLBACK_TARGET: AtomicU32 = AtomicU32::new(0);
static CALLBACK_SAW_UNLOCKED: AtomicBool = AtomicBool::new(false);

fn observe_waiter_change(task: &Arc<Task>) {
    if CALLBACK_TARGET.load(Ordering::Acquire) != task.tid { return; }
    let Some(_pi) = task.pi_lock.try_lock() else { return };
    let Some(rq) = runqueue::global() else { return };
    if rq.inner.try_lock().is_some() { CALLBACK_SAW_UNLOCKED.store(true, Ordering::Release); }
}

fn donor(tid: u32, class: SchedClass) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "donor", class));
    task.set_state(crate::TaskState::Sleeping);
    task
}

fn blocked_owner(tid: u32, class: SchedClass) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "owner", class));
    task.set_state(crate::TaskState::Sleeping);
    task
}

fn dl_donor(tid: u32, deadline: u64) -> Arc<Task> {
    let task = donor(tid, SchedClass::Deadline);
    let mut state = task.sched.dl.sched();
    state.deadline = deadline;
    task.sched.dl.store_sched(&state);
    task
}

struct Installed;

impl Installed {
    fn new(owner: &Arc<Task>) -> Self {
        Self::ordered(core::slice::from_ref(owner))
    }

    fn ordered(tasks: &[Arc<Task>]) -> Self {
        let idle = Arc::new(Task::new(IDLE_TID, "idle", SchedClass::Idle));
        // SAFETY: hosted_global_test_lock serializes the sole hosted CPU's global slot.
        unsafe { runqueue::install_global(Runqueue::new(0, idle)); }
        let rq = runqueue::global().expect("hosted owner rq installed");
        let mut inner = rq.inner.lock();
        for task in tasks { assert!(inner.enqueue(Arc::clone(task))); }
        rq.publish_nr_running(inner.nr_running());
        Self
    }
}

impl Drop for Installed {
    fn drop(&mut self) {
        // SAFETY: fixture owns hosted_global_test_lock and no worker survives teardown.
        let _ = unsafe { runqueue::uninstall_global() };
    }
}

fn wait_until_locked(owner: &Task) -> bool {
    for _ in 0..100_000 {
        if owner.pi_lock.try_lock().is_none() { return true; }
        std::thread::yield_now();
    }
    false
}

#[test]
fn an_unboosted_task_reports_its_own_class_as_its_base() {
    let t = Task::new(7, "t", rt(30));
    assert!(!is_boosted(&t));
    assert_eq!(base_class(&t), rt(30));
}

#[test]
fn a_boosted_task_reports_normal_not_inherited_class() {
    let t = Task::new(8, "t", fair(1024));
    // PI changes only canonical effective priority; normal priority remains
    // the task's configured base.
    t.set_sched_class(rt(70));
    assert!(is_boosted(&t));
    assert_eq!(t.sched_class(), rt(70), "the task really does RUN at the inherited priority");
    assert_eq!(base_class(&t), fair(1024),
               "but sched_getparam and any nested boost computation must see its OWN class");
}

#[test]
fn fork_does_not_inherit_a_pi_donation() {
    let parent = Task::new(9, "parent", fair(1024));
    parent.set_sched_class(rt(80));
    let mut child = Task::new(10, "child", fair(1024));
    crate::live::sched_fork::inherit_sched_params(&mut child, &parent);
    assert_eq!(child.sched_class(), fair(1024));
    assert_eq!(base_class(&child), fair(1024));
    assert!(!is_boosted(&child));
}

#[test]
fn fair_owner_borrows_concrete_deadline_donor() {
    let owner = blocked_owner(11, fair(1024));
    let donor = dl_donor(12, 900);
    crate::live::pi_boost::apply_boost(&owner, Some(Arc::clone(&donor)));
    assert_eq!(owner.sched_class(), SchedClass::Deadline);
    assert_eq!(owner.effective_dl_deadline(), 900);
    let _pi = owner.pi_lock.lock();
    assert!(Arc::ptr_eq(&owner.pi_top_task_unlocked().unwrap(), &donor));
}

#[test]
fn later_deadline_owner_borrows_earlier_donor_then_restores() {
    let owner = dl_donor(13, 400);
    let early = dl_donor(14, 200);
    let late = dl_donor(15, 600);
    pi_boost::apply_boost(&owner, Some(Arc::clone(&early)));
    assert_eq!(owner.effective_dl_deadline(), 200);
    pi_boost::apply_boost(&owner, Some(Arc::clone(&late)));
    assert_eq!(owner.effective_dl_deadline(), 400, "later donor cannot displace owner's earlier entity");
    let _pi = owner.pi_lock.lock();
    assert!(Arc::ptr_eq(&owner.pi_top_task_unlocked().unwrap(), &late));
    drop(_pi);
    pi_boost::deboost(&owner);
    assert_eq!(owner.effective_dl_deadline(), 400);
    assert!(!is_boosted(&owner));
}

#[test]
fn fair_nice_donor_does_not_boost_an_ordinary_owner() {
    let owner = blocked_owner(16, fair(15));
    let high_nice = donor(17, fair(88_761));
    pi_boost::apply_boost(&owner, Some(high_nice));
    assert_eq!(owner.sched_class(), fair(15));
    assert!(is_boosted(&owner), "top donor identity remains attached even when it cannot boost");
    owner.set_nice_value(10);
    assert_eq!(owner.sched_class(), fair(110), "a later nice change must not activate fair donation");
    pi_boost::deboost(&owner);
    assert_eq!(owner.sched_class(), fair(110));
}

#[test]
fn concrete_rt_donor_preserves_owner_policy_rule() {
    let fair_owner = blocked_owner(18, fair(1024));
    let rt70 = donor(19, SchedClass::Rt { prio: 70, policy: SchedPolicy::Rr });
    pi_boost::apply_boost(&fair_owner, Some(Arc::clone(&rt70)));
    assert_eq!(fair_owner.sched_class(), rt(70));

    let rr_owner = blocked_owner(20, SchedClass::Rt {
        prio: 30, policy: SchedPolicy::Rr });
    pi_boost::apply_boost(&rr_owner, Some(rt70));
    assert_eq!(rr_owner.sched_class(), SchedClass::Rt { prio: 70, policy: SchedPolicy::Rr });
}

#[test]
fn deboost_clears_a_donor_that_a_stronger_base_had_masked() {
    let owner = blocked_owner(12, rt(20));
    owner.set_sched_class(rt(40));
    owner.set_normal_sched_class_policy(rt(80), crate::sched_enc::SCHED_FIFO);
    assert_eq!(owner.sched_class(), rt(80));
    assert!(is_boosted(&owner));
    crate::live::pi_boost::deboost(&owner);
    assert_eq!(owner.sched_class(), rt(80));
    assert!(!is_boosted(&owner));
    owner.set_normal_sched_class_policy(rt(20), crate::sched_enc::SCHED_FIFO);
    assert_eq!(owner.sched_class(), rt(20), "departed donor must never be resurrected");
}

#[test]
fn boost_mutation_waits_for_owner_rq_while_holding_task_pi() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    let owner = Arc::new(Task::new(OWNER_TID, "owner", fair(1024)));
    let _installed = Installed::new(&owner);
    let rq = runqueue::global().unwrap();
    let rq_lock = rq.inner.lock();
    let worker_owner = Arc::clone(&owner);
    let worker_donor = donor(OWNER_TID + 100, rt(50));
    let (started_tx, started_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        pi_boost::apply_boost(&worker_owner, Some(worker_donor));
    });

    started_rx.recv().unwrap();
    let pi_held = wait_until_locked(&owner);
    let before_rq = owner.sched_class();
    drop(rq_lock);
    worker.join().unwrap();

    assert!(pi_held, "apply_boost did not hold TaskPi while waiting for owner rq");
    assert_eq!(before_rq, fair(1024),
        "effective PI state changed before the owner rq lock was acquired");
    assert_eq!(owner.sched_class(), rt(50));
    assert!(is_boosted(&owner));
}

#[test]
fn donor_key_snapshot_does_not_settle_or_requeue_a_running_waiter() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    let waiter = Arc::new(Task::new(OWNER_TID + 30, "waiter", rt(55)));
    let _installed = Installed::new(&waiter);
    let rq = runqueue::global().unwrap();
    {
        let mut inner = rq.inner.lock();
        assert!(inner.remove(waiter.tid).is_some());
        rq.current.store(Arc::as_ptr(&waiter).cast_mut(), Ordering::Release);
        waiter.cpu.store(0, Ordering::Release);
        waiter.on_cpu.store(true, Ordering::Release);
    }
    waiter.sched.se.exec_start.store(1, Ordering::Release);
    waiter.sched.se.sum_exec_runtime.store(0, Ordering::Release);

    assert_eq!(pi_boost::donor_key(&waiter).class, rt(55));
    assert_eq!(waiter.sched.se.exec_start.load(Ordering::Acquire), 1);
    assert_eq!(waiter.sched.se.sum_exec_runtime.load(Ordering::Acquire), 0,
        "a PI key read must not run sched_change accounting");
    assert!(!waiter.need_resched.load(Ordering::Acquire));

    rq.current.store(core::ptr::null_mut(), Ordering::Release);
    waiter.on_cpu.store(false, Ordering::Release);
}

#[test]
fn scheduler_policy_commit_notifies_only_after_task_pi_and_rq_unlock() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    let waiter = Arc::new(Task::new(OWNER_TID + 31, "waiter", fair(1024)));
    let _installed = Installed::new(&waiter);
    CALLBACK_SAW_UNLOCKED.store(false, Ordering::Release);
    CALLBACK_TARGET.store(waiter.tid, Ordering::Release);
    let _hook = pi_boost::scoped_test_waiter_change_hook(observe_waiter_change);

    pi_boost::set_base_class(&waiter, rt(60));

    CALLBACK_TARGET.store(0, Ordering::Release);
    assert!(CALLBACK_SAW_UNLOCKED.load(Ordering::Acquire),
        "post-policy PI adjustment ran while TaskPi or rq was still held");
}

#[test]
fn scheduler_apply_update_notifies_only_after_task_pi_and_rq_unlock() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    let waiter = Arc::new(Task::new(OWNER_TID + 32, "waiter", fair(1024)));
    let _installed = Installed::new(&waiter);
    CALLBACK_SAW_UNLOCKED.store(false, Ordering::Release);
    CALLBACK_TARGET.store(waiter.tid, Ordering::Release);
    let _hook = pi_boost::scoped_test_waiter_change_hook(observe_waiter_change);
    let update = crate::SchedUpdate {
        class: rt(60), policy: crate::sched_enc::SCHED_FIFO,
        clamp: crate::SchedUclamp::new(0, crate::sched_enc::UCLAMP_CAPACITY_SCALE, 0).unwrap(),
        reset_on_fork: false, nice: None, fair_slice: None,
        reload_rt_timeslice: false, clear_rt_timeout: true, deadline: None,
    };

    assert_eq!(runqueue::apply_update(&waiter, waiter.sched_policy_generation(), update),
        crate::SchedUpdateResult::Applied);

    CALLBACK_TARGET.store(0, Ordering::Release);
    assert!(CALLBACK_SAW_UNLOCKED.load(Ordering::Acquire),
        "post-policy PI adjustment ran while TaskPi or rq was still held");
}

#[test]
fn concurrent_newer_rt80_base_cannot_be_demoted_by_rt50_donation() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    let owner = Arc::new(Task::new(OWNER_TID + 1, "owner", fair(1024)));
    let _installed = Installed::new(&owner);
    let rq = runqueue::global().unwrap();
    let rq_lock = rq.inner.lock();

    let base_owner = Arc::clone(&owner);
    let base_worker = std::thread::spawn(move || pi_boost::set_base_class(&base_owner, rt(80)));
    let base_holds_pi = wait_until_locked(&owner);

    let boost_entered = StdArc::new(AtomicBool::new(false));
    let entered = StdArc::clone(&boost_entered);
    let boost_owner = Arc::clone(&owner);
    let boost_donor = donor(OWNER_TID + 101, rt(50));
    let boost_worker = std::thread::spawn(move || {
        entered.store(true, Ordering::Release);
        pi_boost::apply_boost(&boost_owner, Some(boost_donor));
    });
    while !boost_entered.load(Ordering::Acquire) { std::thread::yield_now(); }
    for _ in 0..1_000 { std::thread::yield_now(); }

    drop(rq_lock);
    base_worker.join().unwrap();
    boost_worker.join().unwrap();

    assert!(base_holds_pi, "base update did not hold TaskPi before boost entered");
    assert_eq!(base_class(&owner), rt(80));
    assert_eq!(owner.sched_class(), rt(80),
        "a stale RT50 donation demoted the newer RT80 configured base");
    assert!(is_boosted(&owner), "the concrete top waiter remains attached while base wins");
}

#[test]
fn positive_control_stale_precompute_would_demote_newer_base() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    let owner = Arc::new(Task::new(OWNER_TID + 2, "owner", fair(1024)));
    let _installed = Installed::new(&owner);
    let stale = crate::pi_prio::boost_class(base_class(&owner), &[rt(50)]).unwrap();

    pi_boost::set_base_class(&owner, rt(80));
    runqueue::mutate_effective(&owner, |task| task.sched.store_effective_class(stale));

    assert_eq!(base_class(&owner), rt(80));
    assert_eq!(owner.sched_class(), rt(50),
        "positive control no longer reproduces stale-precompute demotion");
}

#[test]
fn weaker_base_change_under_donation_preserves_queue_position() {
    let owner = Arc::new(Task::new(OWNER_TID + 3, "owner", fair(1024)));
    owner.sched.store_effective_class(rt(50));
    let update = crate::SchedUpdate {
        class: fair(820), policy: crate::sched_enc::SCHED_NORMAL,
        clamp: crate::SchedUclamp::new(0, 1024, 0).unwrap(),
        reset_on_fork: false, nice: Some(1), fair_slice: None,
        reload_rt_timeslice: false, clear_rt_timeout: true, deadline: None,
    };

    assert!(!owner.sched_update_moves_queue(update),
        "a weaker base update moved an unchanged donated effective priority");
}

#[test]
fn repeated_identical_pi_boost_preserves_rt_peer_order() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    let peer = Arc::new(Task::new(OWNER_TID + 10, "peer", rt(50)));
    let owner = blocked_owner(OWNER_TID + 11, rt(30));
    let donor = donor(OWNER_TID + 110, rt(50));
    pi_boost::apply_boost(&owner, Some(Arc::clone(&donor)));
    owner.set_state(crate::TaskState::Runnable);
    let _installed = Installed::ordered(&[Arc::clone(&peer), Arc::clone(&owner)]);

    pi_boost::apply_boost(&owner, Some(Arc::clone(&donor)));
    pi_boost::apply_boost(&owner, Some(donor));

    let rq = runqueue::global().unwrap();
    let mut inner = rq.inner.lock();
    assert_eq!(inner.pick_next_task().tid, peer.tid,
        "an identical PI boost moved the owner ahead of its RT peer");
    assert_eq!(inner.pick_next_task().tid, owner.tid);
}

#[test]
fn deboost_of_unboosted_task_preserves_rt_peer_order() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    let peer = Arc::new(Task::new(OWNER_TID + 12, "peer", rt(30)));
    let owner = Arc::new(Task::new(OWNER_TID + 13, "owner", rt(30)));
    let _installed = Installed::ordered(&[Arc::clone(&peer), Arc::clone(&owner)]);

    pi_boost::deboost(&owner);

    let rq = runqueue::global().unwrap();
    let mut inner = rq.inner.lock();
    assert_eq!(inner.pick_next_task().tid, peer.tid,
        "deboosting an unboosted task moved it ahead of its RT peer");
    assert_eq!(inner.pick_next_task().tid, owner.tid);
}

#[test]
fn positive_control_unconditional_requeue_moves_rt_tail_to_head() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    let peer = Arc::new(Task::new(OWNER_TID + 14, "peer", rt(30)));
    let owner = Arc::new(Task::new(OWNER_TID + 15, "owner", rt(30)));
    let _installed = Installed::ordered(&[Arc::clone(&peer), Arc::clone(&owner)]);
    let rq = runqueue::global().unwrap();
    let mut inner = rq.inner.lock();

    let moved = inner.remove(owner.tid).expect("owner queued");
    assert!(inner.enqueue_at(moved, crate::sched_enc::requeue::RequeuePos::Head));

    assert_eq!(inner.pick_next_task().tid, owner.tid,
        "positive control no longer reproduces unconditional PI reorder");
}

#[test]
fn unchanged_nice_returns_without_reordering_rt_peers() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    let peer = Arc::new(Task::new(OWNER_TID + 16, "peer", rt(30)));
    let owner = Arc::new(Task::new(OWNER_TID + 17, "owner", rt(30)));
    let _installed = Installed::ordered(&[Arc::clone(&peer), Arc::clone(&owner)]);

    runqueue::set_nice(&owner, owner.nice_value());

    let rq = runqueue::global().unwrap();
    let mut inner = rq.inner.lock();
    assert_eq!(inner.pick_next_task().tid, peer.tid);
    assert_eq!(inner.pick_next_task().tid, owner.tid);
}

#[test]
fn rt_nice_update_is_latent_and_preserves_queue_position() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    let peer = Arc::new(Task::new(OWNER_TID + 18, "peer", rt(30)));
    let owner = Arc::new(Task::new(OWNER_TID + 19, "owner", rt(30)));
    let _installed = Installed::ordered(&[Arc::clone(&peer), Arc::clone(&owner)]);

    runqueue::set_nice(&owner, 7);

    assert_eq!(owner.nice_value(), 7);
    assert_eq!(owner.sched_class(), rt(30));
    let rq = runqueue::global().unwrap();
    let mut inner = rq.inner.lock();
    assert_eq!(inner.pick_next_task().tid, peer.tid);
    assert_eq!(inner.pick_next_task().tid, owner.tid);
}

#[test]
fn deadline_nice_update_is_latent_and_keeps_ready_ownership() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    let owner = Arc::new(Task::new(OWNER_TID + 20, "owner", SchedClass::Deadline));
    let _installed = Installed::new(&owner);

    runqueue::set_nice(&owner, 9);

    assert_eq!(owner.nice_value(), 9);
    assert_eq!(owner.sched_class(), SchedClass::Deadline);
    assert!(owner.on_rq.is_queued(Ordering::Acquire));
    assert!(owner.on_class_rq.load(Ordering::Acquire));
    assert_eq!(runqueue::global().unwrap().inner.lock().nr_running(), 1);
}

#[test]
#[should_panic(expected = "PI base update cannot bypass deadline admission")]
fn pi_base_update_cannot_install_deadline_without_admission() {
    let owner = Arc::new(Task::new(OWNER_TID + 21, "owner", fair(1024)));
    pi_boost::set_base_class(&owner, SchedClass::Deadline);
}
