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
