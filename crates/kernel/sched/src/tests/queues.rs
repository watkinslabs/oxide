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
    q.enqueue(rt(2, 30));
    q.enqueue(rt(3, 60));
    let t = q.remove(2).unwrap();
    assert_eq!(t.tid, 2);
    assert_eq!(q.nr_running(), 2);
    assert_eq!(q.pick_highest().unwrap().tid, 3);
    assert_eq!(q.pick_highest().unwrap().tid, 1);
}

#[test]
fn rt_remove_clears_bitmap_when_bucket_empty() {
    let mut q = RtRunqueue::new();
    q.enqueue(rt(1, 50));
    q.remove(1).unwrap();
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
    q.enqueue(normal(2, 20, 1024));
    let t = q.remove(2).unwrap();
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
fn rq_enqueue_idle_panics() {
    let mut rq = RunqueueInner::new(0, idle(0));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rq.enqueue(idle(99));
    }));
    assert!(result.is_err(), "enqueueing an Idle-class task must panic");
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
        t.vruntime.fetch_add(SLICE, Ordering::AcqRel);
        q.enqueue(t);
    }
    assert_eq!(order, alloc::vec![1u32, 2, 3, 1, 2, 3, 1, 2, 3],
        "equal-weight tasks must round-robin in stable order");
}

// Linux `__schedule`'s `prepare_task(next)` store order: `on_cpu` goes up
// BEFORE the task leaves the tree (`on_rq` goes down). `kernel/sched/core.c`
// spells the pairing out next to ttwu's `smp_load_acquire(&p->on_cpu)`:
//
//   __schedule() (switch to task 'p')      try_to_wake_up()
//     STORE p->on_cpu = 1                    LOAD p->on_rq
//   __schedule() (put 'p' to sleep)
//     STORE p->on_rq = 0                     LOAD p->on_cpu
//
// "One must be running (->on_cpu == 1) in order to remove oneself from the
// runqueue" — so a reader must never observe BOTH clear for a task being
// switched to. `Task::pending_wake` is that reader.

use crate::task::PendingWake;

#[test]
fn claiming_pick_publishes_on_cpu_and_clears_on_rq() {
    let mut rq = RunqueueInner::new(0, idle(0));
    let t = normal(30, 0, 1024);
    rq.enqueue(Arc::clone(&t));
    assert!(t.on_rq.load(Ordering::Acquire));

    let (picked, already) = rq.pick_next_task_claim();

    assert_eq!(picked.tid, 30);
    assert!(!already, "nobody owned this task before the pick");
    assert!(picked.on_cpu.load(Ordering::Acquire), "prepare_task(next) did not publish on_cpu");
    assert!(!picked.on_rq.load(Ordering::Acquire), "the pick must take it out of the tree");
}

/// The window the store order closes: at EVERY point observable by a
/// concurrent wake-list drain, the task being switched to must look
/// "executing" (Defer), never "safe to enqueue" (Ready).
#[test]
fn a_task_being_switched_to_is_never_reported_enqueueable() {
    let mut rq = RunqueueInner::new(0, idle(0));
    let t = normal(31, 0, 1024);
    rq.enqueue(Arc::clone(&t));

    // Before the pick: queued, so a drain drops the wake.
    assert!(matches!(t.pending_wake(core::ptr::null_mut()), PendingWake::Drop));

    let (picked, _) = rq.pick_next_task_claim();

    // After the pick: executing, so a drain defers it to the owner CPU.
    assert!(matches!(picked.pending_wake(core::ptr::null_mut()), PendingWake::Defer),
        "a task mid-switch-to was reported ready to enqueue on another CPU");
}

/// Reproduces the pre-fix order literally — pick first, publish `on_cpu`
/// after — and shows the reader falsely observes Ready in between. Without
/// this, the test above could pass against a broken probe.
#[test]
fn probe_detects_the_pre_fix_pick_then_claim_window() {
    let mut rq = RunqueueInner::new(0, idle(0));
    let t = normal(32, 0, 1024);
    rq.enqueue(Arc::clone(&t));

    // Pre-fix body: `pick_next_task()` (clears on_rq), THEN set on_cpu.
    let picked = rq.pick_next_task();
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
