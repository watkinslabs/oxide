use super::common::{idle, normal, rt};
use crate::cfs::CfsRunqueue;
use crate::rt::{RtRunqueue, RT_PRIO_COUNT};
use crate::runqueue::RunqueueInner;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

#[test]
fn rt_empty() {
    let q = RtRunqueue::new();
    assert!(!q.has_runnable());
    assert_eq!(q.nr_running(), 0);
}

#[test]
fn rt_pick_highest_priority_first() {
    let mut q = RtRunqueue::new();
    q.enqueue(rt(1, 10));
    q.enqueue(rt(2, 99));
    q.enqueue(rt(3, 50));
    let t = q.pick_highest().unwrap();
    assert_eq!(t.tid, 2);
    let t = q.pick_highest().unwrap();
    assert_eq!(t.tid, 3);
    let t = q.pick_highest().unwrap();
    assert_eq!(t.tid, 1);
    assert!(q.pick_highest().is_none());
}

#[test]
fn rt_fifo_within_priority() {
    let mut q = RtRunqueue::new();
    q.enqueue(rt(10, 50));
    q.enqueue(rt(11, 50));
    q.enqueue(rt(12, 50));
    assert_eq!(q.pick_highest().unwrap().tid, 10);
    assert_eq!(q.pick_highest().unwrap().tid, 11);
    assert_eq!(q.pick_highest().unwrap().tid, 12);
}

#[test]
fn rt_remove_by_tid() {
    let mut q = RtRunqueue::new();
    q.enqueue(rt(1, 30));
    let removed = rt(2, 30);
    q.enqueue(Arc::clone(&removed));
    q.enqueue(rt(3, 60));
    let t = q.remove(&removed).unwrap();
    assert_eq!(t.tid, 2);
    assert_eq!(q.nr_running(), 2);
    assert_eq!(q.pick_highest().unwrap().tid, 3);
    assert_eq!(q.pick_highest().unwrap().tid, 1);
}

#[test]
fn rt_remove_clears_bitmap_when_bucket_empty() {
    let mut q = RtRunqueue::new();
    let task = rt(1, 50);
    q.enqueue(Arc::clone(&task));
    q.remove(&task).unwrap();
    assert!(!q.has_runnable());
}

#[test]
fn rt_peek_does_not_remove() {
    let mut q = RtRunqueue::new();
    q.enqueue(rt(1, 99));
    let peek_tid = q.peek_highest().unwrap().tid;
    assert_eq!(peek_tid, 1);
    assert_eq!(q.nr_running(), 1);
}

#[test]
fn rt_priority_constant_matches_spec() {
    assert_eq!(RT_PRIO_COUNT, 100);
}

#[test]
fn cfs_pick_leftmost_lowest_vruntime() {
    let mut q = CfsRunqueue::new();
    q.enqueue(normal(1, 100, 1024));
    q.enqueue(normal(2, 50, 1024));
    q.enqueue(normal(3, 200, 1024));
    assert_eq!(q.pick_leftmost().unwrap().tid, 2);
    assert_eq!(q.pick_leftmost().unwrap().tid, 1);
    assert_eq!(q.pick_leftmost().unwrap().tid, 3);
    assert!(q.pick_leftmost().is_none());
}

#[test]
fn cfs_eevdf_rejects_ineligible_late_vruntime() {
    let mut q = CfsRunqueue::new();
    let early = normal(1, 100, 1024);
    let eligible = normal(2, 200, 1024);
    let late = normal(3, 300, 1024);
    q.enqueue(Arc::clone(&early));
    q.enqueue(Arc::clone(&eligible));
    q.enqueue(Arc::clone(&late));
    // The virtual deadline is deliberately controlled here so this test
    // isolates EEVDF eligibility from the default-slice calculation.
    early.sched.se.deadline.store(900, Ordering::Release);
    eligible.sched.se.deadline.store(500, Ordering::Release);
    late.sched.se.deadline.store(1, Ordering::Release);
    assert_eq!(q.pick_leftmost().unwrap().tid, 2);
}

#[test]
fn cfs_min_vruntime_tracks_leftmost() {
    let mut q = CfsRunqueue::new();
    q.enqueue(normal(1, 100, 1024));
    q.enqueue(normal(2, 50, 1024));
    assert_eq!(q.min_vruntime(), 50);
    q.pick_leftmost().unwrap();
    assert_eq!(q.min_vruntime(), 100);
    q.pick_leftmost().unwrap();
    assert_eq!(q.min_vruntime(), 0);
}

#[test]
fn cfs_max_vruntime_tracks_rightmost() {
    let mut q = CfsRunqueue::new();
    assert_eq!(q.max_vruntime(), 0);
    q.enqueue(normal(1, 100, 1024));
    q.enqueue(normal(2, 50, 1024));
    q.enqueue(normal(3, 200, 1024));
    assert_eq!(q.max_vruntime(), 200);
    assert_eq!(q.pick_leftmost().unwrap().tid, 2);
    assert_eq!(q.max_vruntime(), 200);
}

#[test]
fn cfs_ties_disambiguated_by_tid() {
    let mut q = CfsRunqueue::new();
    q.enqueue(normal(7, 100, 1024));
    q.enqueue(normal(3, 100, 1024));
    q.enqueue(normal(5, 100, 1024));
    assert_eq!(q.pick_leftmost().unwrap().tid, 3);
    assert_eq!(q.pick_leftmost().unwrap().tid, 5);
    assert_eq!(q.pick_leftmost().unwrap().tid, 7);
}

#[test]
fn cfs_remove_by_tid() {
    let mut q = CfsRunqueue::new();
    q.enqueue(normal(1, 10, 1024));
    let removed = normal(2, 20, 1024);
    q.enqueue(Arc::clone(&removed));
    let t = q.remove(&removed).unwrap();
    assert_eq!(t.tid, 2);
    assert_eq!(q.nr_running(), 1);
    assert_eq!(q.pick_leftmost().unwrap().tid, 1);
}

#[test]
fn rq_idle_picked_when_empty() {
    let id = idle(0);
    let mut rq = RunqueueInner::new(0, Arc::clone(&id));
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, id.tid);
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, id.tid);
}

#[test]
fn rq_rt_preempts_normal_invariant_6() {
    let mut rq = RunqueueInner::new(0, idle(0));
    rq.enqueue(normal(10, 0, 1024));
    rq.enqueue(rt(20, 50));
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, 20);
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, 10);
}

#[test]
fn rq_idle_only_when_no_runnable_invariant_7() {
    let id = idle(0);
    let mut rq = RunqueueInner::new(0, Arc::clone(&id));
    rq.enqueue(normal(1, 5, 1024));
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, 1);
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, id.tid);
}

#[test]
fn rq_enqueue_idle_is_rejected() {
    let mut rq = RunqueueInner::new(0, idle(0));
    let task = idle(99);
    assert!(!rq.enqueue(Arc::clone(&task)));
    assert!(!task.on_rq.load(Ordering::Acquire));
    assert!(!task.on_class_rq.load(Ordering::Acquire));
}

#[test]
fn rq_remove_finds_in_either_class() {
    let mut rq = RunqueueInner::new(0, idle(0));
    rq.enqueue(rt(1, 20));
    rq.enqueue(normal(2, 100, 1024));
    let a = rq.remove(2).unwrap();
    assert_eq!(a.tid, 2);
    let b = rq.remove(1).unwrap();
    assert_eq!(b.tid, 1);
    assert!(rq.remove(99).is_none());
}

#[test]
fn rq_peek_does_not_drain() {
    let mut rq = RunqueueInner::new(0, idle(0));
    rq.enqueue(rt(7, 80));
    let p = rq.peek_next_task();
    assert_eq!(p.tid, 7);
    assert_eq!(rq.nr_running(), 1);
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, 7);
    assert_eq!(rq.nr_running(), 0);
}

#[test]
fn rq_enqueue_skips_frozen_task() {
    let mut rq = RunqueueInner::new(0, idle(0));
    let t = normal(5, 100, 1024);
    t.frozen.store(true, Ordering::Release);
    rq.enqueue(Arc::clone(&t));
    assert_eq!(rq.nr_running(), 0, "frozen task must not enter the runqueue");
    t.frozen.store(false, Ordering::Release);
    rq.enqueue(t);
    assert_eq!(rq.nr_running(), 1, "thawed task must enqueue");
    assert_eq!(rq.pick_next_task().tid, 5);
}

#[test]
fn rq_enqueue_stamps_task_cpu_owner() {
    let mut rq = RunqueueInner::new(3, idle(0));
    let t = normal(9, 100, 1024);
    rq.enqueue(Arc::clone(&t));
    assert_eq!(t.cpu.load(Ordering::Acquire), 3);
}

#[test]
fn rq_sched_yield_normal_forfeits_cfs_position() {
    let mut rq = RunqueueInner::new(0, idle(0));
    let current = normal(1, 0, 1024);
    rq.enqueue(normal(2, 0, 1024));
    rq.enqueue(normal(3, 5, 1024));

    rq.yield_current_task(&current);
    rq.enqueue(Arc::clone(&current));

    assert_eq!(rq.pick_next_task().tid, 2);
    assert_eq!(rq.pick_next_task().tid, 3);
    assert_eq!(rq.pick_next_task().tid, 1);
}

#[test]
fn rq_sched_yield_rt_requeues_current_at_fifo_tail() {
    let mut rq = RunqueueInner::new(0, idle(0));
    let current = rt(1, 50);
    rq.enqueue(rt(2, 50));

    rq.yield_current_task(&current);
    rq.enqueue(Arc::clone(&current));

    assert_eq!(rq.pick_next_task().tid, 2);
    assert_eq!(rq.pick_next_task().tid, 1);
}

#[test]
fn cfs_rotation_is_round_robin_for_equal_weight() {
    let mut q = CfsRunqueue::new();
    let tasks = [normal(1, 0, 1024), normal(2, 0, 1024), normal(3, 0, 1024)];
    for t in tasks.iter() { q.enqueue(Arc::clone(t)); }
    const SLICE: u64 = 1000;
    let mut order = alloc::vec::Vec::new();
    for _ in 0..9 {
        let t = q.pick_leftmost().unwrap();
        order.push(t.tid);
        t.sched.se.vruntime.fetch_add(SLICE, Ordering::AcqRel);
        q.enqueue(t);
    }
    assert_eq!(order, alloc::vec![1u32, 2, 3, 1, 2, 3, 1, 2, 3],
        "equal-weight tasks must round-robin in stable order");
}

// Linux keeps task `on_rq == QUEUED` while a running runnable entity is off
// its class tree. The exact task selected by policy receives `on_cpu`, paired
// against
// `try_to_wake_up`'s `smp_load_acquire(&p->on_cpu)`:
//
//   __schedule() (switch to task 'p')      try_to_wake_up()
//     STORE p->on_cpu = 1                    LOAD p->on_rq
//   __schedule() (put 'p' to sleep)
//     STORE p->on_rq = 0                     LOAD p->on_cpu
//
// Invariant: a task must be running (on_cpu == 1) to remove itself from the
// runqueue — so a reader must never observe BOTH clear for a task being
// switched to. `Task::pending_wake` is that reader.

use crate::task::PendingWake;

#[test]
fn claiming_pick_preserves_on_rq_and_clears_class_membership() {
    let mut rq = RunqueueInner::new(0, idle(0));
    let t = normal(30, 0, 1024);
    rq.enqueue(Arc::clone(&t));
    assert!(t.on_rq.load(Ordering::Acquire));
    assert!(t.on_class_rq.load(Ordering::Acquire));

    let (picked, already) = rq.pick_next_task_claim();

    assert_eq!(picked.tid, 30);
    assert!(!already, "nobody owned this task before the pick");
    assert!(picked.on_cpu.load(Ordering::Acquire), "prepare_task(next) did not publish on_cpu");
    assert!(picked.on_rq.is_queued(Ordering::Acquire),
        "a running runnable task must remain canonically queued");
    assert!(!picked.on_class_rq.load(Ordering::Acquire),
        "the pick must take the entity out of its class tree");
}

/// EEVDF selection is not the fair tree's leftmost-vruntime ordering. This is
/// the KI-0327 positive control: the old peek-then-pick transaction claimed
/// `leftmost` but returned `selected`, leaving `leftmost.on_cpu` orphaned for a
/// later CPU to diagnose as double ownership.
#[test]
fn claiming_pick_owns_the_exact_eevdf_selected_task() {
    let mut rq = RunqueueInner::new(0, idle(0));
    let leftmost = normal(34, 100, 1024);
    let selected = normal(35, 200, 1024);
    let ineligible = normal(36, 300, 1024);
    rq.enqueue(Arc::clone(&leftmost));
    rq.enqueue(Arc::clone(&selected));
    rq.enqueue(Arc::clone(&ineligible));

    leftmost.sched.se.deadline.store(900, Ordering::Release);
    selected.sched.se.deadline.store(500, Ordering::Release);
    ineligible.sched.se.deadline.store(1, Ordering::Release);
    assert_eq!(rq.peek_next_task().tid, leftmost.tid,
        "positive control requires fair peek and EEVDF selection to differ");

    let (picked, already) = rq.pick_next_task_claim();

    assert_eq!(picked.tid, selected.tid);
    assert!(!already, "the selected task started unowned");
    assert!(selected.on_cpu.load(Ordering::Acquire),
        "prepare_task must claim the task returned by policy selection");
    assert!(!leftmost.on_cpu.load(Ordering::Acquire),
        "a non-selected fair-tree task must not retain CPU ownership");
    assert!(!ineligible.on_cpu.load(Ordering::Acquire),
        "an ineligible fair task must not retain CPU ownership");
}

/// The window the store order closes: at EVERY point observable by a
/// concurrent wake-list drain, the task being switched to remains runnable,
/// so another wake is redundant rather than safe to enqueue.
#[test]
fn a_task_being_switched_to_is_never_reported_enqueueable() {
    let mut rq = RunqueueInner::new(0, idle(0));
    let t = normal(31, 0, 1024);
    rq.enqueue(Arc::clone(&t));

    // Before the pick: queued, so a drain drops the wake.
    assert!(matches!(t.pending_wake(core::ptr::null_mut()), PendingWake::Drop));

    let (picked, _) = rq.pick_next_task_claim();

    // After the pick: canonically queued and executing, so a drain drops it.
    assert!(matches!(picked.pending_wake(core::ptr::null_mut()), PendingWake::Drop),
        "a task mid-switch-to was reported ready to enqueue on another CPU");
}

/// Reproduces the old split-source model by clearing canonical `on_rq` when
/// the class tree removes the entity. The wake probe must expose that window.
#[test]
fn probe_detects_the_pre_fix_pick_then_claim_window() {
    let mut rq = RunqueueInner::new(0, idle(0));
    let t = normal(32, 0, 1024);
    rq.enqueue(Arc::clone(&t));

    // Pre-fix body: class pick incorrectly clears task on_rq before on_cpu.
    let picked = rq.pick_next_task();
    picked.on_rq.store(false, Ordering::Release);
    assert!(matches!(picked.pending_wake(core::ptr::null_mut()), PendingWake::Ready),
        "probe failed to observe the falsely-enqueueable window Linux warns about");
    picked.on_cpu.store(true, Ordering::Release);
}

/// A re-pick of the task already running here (`schedule()` selecting `prev`
/// again) reports `already == true`; that is the signal `schedule()` uses to
/// distinguish its own task from one another CPU owns.
#[test]
fn claiming_pick_reports_an_already_owned_task() {
    let mut rq = RunqueueInner::new(0, idle(0));
    let t = normal(33, 0, 1024);
    t.on_cpu.store(true, Ordering::Release);
    rq.enqueue(Arc::clone(&t));

    let (picked, already) = rq.pick_next_task_claim();

    assert_eq!(picked.tid, 33);
    assert!(already, "an already-executing task must be reported as already owned");
}

/// Falling through to idle claims the idle task, not a stale tree entry.
#[test]
fn claiming_pick_of_an_empty_runqueue_claims_idle() {
    let id = idle(0);
    let mut rq = RunqueueInner::new(0, Arc::clone(&id));

    let (picked, already) = rq.pick_next_task_claim();

    assert_eq!(picked.tid, id.tid);
    assert!(!already);
    assert!(id.on_cpu.load(Ordering::Acquire));
}

// ---------------------------------------------------------------------------
// put_prev_task position: what separates SCHED_FIFO from SCHED_RR
// ---------------------------------------------------------------------------

#[test]
fn a_preempted_rt_task_resumes_ahead_of_its_equal_priority_peers() {
    let mut rq = RunqueueInner::new(0, idle(0));
    let current = rt(1, 50);
    rq.enqueue(rt(2, 50));
    rq.enqueue(rt(3, 50));

    // Involuntary preemption: nothing marked the task as having given up its
    // turn, so it must come back at the HEAD and be picked again first.
    rq.put_prev_task(Arc::clone(&current));

    assert_eq!(rq.pick_next_task().tid, 1);
    assert_eq!(rq.pick_next_task().tid, 2);
    assert_eq!(rq.pick_next_task().tid, 3);
}

#[test]
fn repeated_preemption_never_demotes_a_fifo_task() {
    // The regression: every put_prev_task used to push to the tail, so N
    // preemptions moved a FIFO task N places back through its peers.
    let mut rq = RunqueueInner::new(0, idle(0));
    let current = rt(1, 50);
    rq.enqueue(rt(2, 50));

    for _ in 0..50 {
        rq.put_prev_task(Arc::clone(&current));
        assert_eq!(rq.pick_next_task().tid, 1);
    }
    assert_eq!(rq.pick_next_task().tid, 2);
}

#[test]
fn a_spent_round_robin_quantum_rotates_the_task() {
    let mut rq = RunqueueInner::new(0, idle(0));
    let current = rt(1, 50);
    rq.enqueue(rt(2, 50));
    rq.enqueue(rt(3, 50));

    // What the tick sets when an RR quantum runs out with a peer present.
    current.rt_requeue_tail.store(true, Ordering::Release);
    rq.put_prev_task(Arc::clone(&current));

    assert_eq!(rq.pick_next_task().tid, 2);
    assert_eq!(rq.pick_next_task().tid, 3);
    assert_eq!(rq.pick_next_task().tid, 1);
}

#[test]
fn the_rotation_request_is_consumed_by_one_requeue() {
    // A single spent quantum must rotate the task once, not forever.
    let mut rq = RunqueueInner::new(0, idle(0));
    let current = rt(1, 50);
    rq.enqueue(rt(2, 50));

    current.rt_requeue_tail.store(true, Ordering::Release);
    rq.put_prev_task(Arc::clone(&current));
    assert!(!current.rt_requeue_tail.load(Ordering::Acquire));
    assert_eq!(rq.pick_next_task().tid, 2);

    // Next preemption is involuntary again, so the task keeps its place.
    rq.put_prev_task(Arc::clone(&current));
    assert_eq!(rq.pick_next_task().tid, 1);
}

#[test]
fn a_woken_rt_task_joins_behind_an_equal_priority_task_already_waiting() {
    // The head position is for a preempted task only; a fresh wakeup must not
    // jump ahead of a peer that has been waiting.
    let mut rq = RunqueueInner::new(0, idle(0));
    rq.enqueue(rt(2, 50));
    rq.enqueue(rt(3, 50));

    assert_eq!(rq.pick_next_task().tid, 2);
    assert_eq!(rq.pick_next_task().tid, 3);
}

#[test]
fn priority_still_beats_position() {
    let mut rq = RunqueueInner::new(0, idle(0));
    let current = rt(1, 50);
    rq.enqueue(rt(2, 60));

    // Head-of-its-own-bucket does not promote a task above a higher priority.
    rq.put_prev_task(Arc::clone(&current));
    assert_eq!(rq.pick_next_task().tid, 2);
    assert_eq!(rq.pick_next_task().tid, 1);
}

#[test]
fn cgroup_share_changes_eevdf_request_without_changing_nice_weight() {
    let mut q = CfsRunqueue::new();
    let low = normal(90, 0, 1024);
    let high = normal(91, 0, 1024);
    low.sched.store_group_shares(512);
    high.sched.store_group_shares(2048);
    q.enqueue(Arc::clone(&low));
    q.enqueue(Arc::clone(&high));
    assert!(high.sched.se.deadline.load(Ordering::Acquire)
        < low.sched.se.deadline.load(Ordering::Acquire));
    assert_eq!(low.sched.se.load.snapshot().weight, high.sched.se.load.snapshot().weight);
}

#[test]
fn cfs_descends_through_parent_group_entities() {
    let mut q = CfsRunqueue::new();
    let first = normal(92, 0, 1024);
    let second = normal(93, 0, 1024);
    first.sched.store_group_id(10);
    second.sched.store_group_id(20);
    first.sched.store_group_shares(1024);
    second.sched.store_group_shares(512);
    q.enqueue(Arc::clone(&first));
    q.enqueue(Arc::clone(&second));
    assert_eq!(q.pick_leftmost().unwrap().tid, 92);
    assert_eq!(q.pick_leftmost().unwrap().tid, 93);
}
