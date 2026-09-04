use super::common::{normal, rt};
use crate::cfs::CfsRunqueue;
use crate::deadline::{DlParams, DlSched};
use crate::dl::DlRunqueue;
use crate::rt::RtRunqueue;
use crate::sched_enc::requeue::RequeuePos;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

fn deadline(tid: u32, absolute: u64) -> Arc<crate::Task> {
    let task = Arc::new(crate::Task::new(tid, "deadline", crate::SchedClass::Deadline));
    task.sched.dl.set_params(&DlParams::from_request(1, 1_000, 1_000, 0));
    task.sched.dl.store_sched(&DlSched {
        runtime: 1, deadline: absolute, throttled: false, yielded: false, overrun: false,
    });
    task
}

#[test]
fn rt_head_insert_marks_inserted_entity() {
    let mut q = RtRunqueue::new();
    let old_tail = rt(10, 50);
    let new_head = rt(11, 50);
    assert!(q.enqueue(Arc::clone(&old_tail)));
    assert!(q.enqueue_at(Arc::clone(&new_head), RequeuePos::Head));
    assert!(new_head.sched.rt.on_list.load(Ordering::Acquire));
    assert!(new_head.sched.rt.on_rq.load(Ordering::Acquire));
    assert!(old_tail.sched.rt.on_list.load(Ordering::Acquire));
    assert!(old_tail.sched.rt.on_rq.load(Ordering::Acquire));
    assert_eq!(q.pick_highest().unwrap().tid, new_head.tid);
    assert!(!new_head.sched.rt.on_list.load(Ordering::Acquire));
    assert!(!new_head.sched.rt.on_rq.load(Ordering::Acquire));
    assert!(old_tail.sched.rt.on_list.load(Ordering::Acquire));
    assert!(old_tail.sched.rt.on_rq.load(Ordering::Acquire));
}

#[test]
fn rt_task_cannot_alias_two_class_queues() {
    let task = rt(20, 60);
    let mut owner = RtRunqueue::new();
    let mut contender = RtRunqueue::new();
    assert!(owner.enqueue(Arc::clone(&task)));
    assert!(!contender.enqueue(Arc::clone(&task)));
    assert!(contender.remove(&task).is_none());
    assert_eq!(owner.nr_running(), 1);
    assert_eq!(contender.nr_running(), 0);
    assert_eq!(owner.pick_highest().unwrap().tid, task.tid);
    assert!(contender.enqueue(Arc::clone(&task)));
    assert_eq!(contender.pick_highest().unwrap().tid, task.tid);
}

#[test]
fn rt_drop_detaches_embedded_links() {
    let first = rt(30, 40);
    let second = rt(31, 40);
    {
        let mut q = RtRunqueue::new();
        assert!(q.enqueue(Arc::clone(&first)));
        assert!(q.enqueue(Arc::clone(&second)));
    }
    for task in [&first, &second] {
        assert!(!task.on_class_rq.load(Ordering::Acquire));
        assert!(!task.sched.rt.on_list.load(Ordering::Acquire));
        assert!(!task.sched.rt.on_rq.load(Ordering::Acquire));
    }
    let mut q = RtRunqueue::new();
    assert!(q.enqueue(Arc::clone(&first)));
    assert_eq!(q.pick_highest().unwrap().tid, first.tid);
}

#[test]
fn cfs_task_cannot_alias_two_class_queues() {
    let task = normal(20, 100, 1024);
    let mut owner = CfsRunqueue::new();
    let mut contender = CfsRunqueue::new();
    assert!(owner.enqueue(Arc::clone(&task)));
    assert!(!contender.enqueue(Arc::clone(&task)));
    assert!(contender.remove(&task).is_none());
    assert_eq!(owner.nr_running(), 1);
    assert_eq!(contender.nr_running(), 0);
    assert_eq!(owner.pick_leftmost().unwrap().tid, task.tid);
    assert!(contender.enqueue(Arc::clone(&task)));
    assert_eq!(contender.pick_leftmost().unwrap().tid, task.tid);
}

#[test]
fn cfs_drop_detaches_embedded_links() {
    let first = normal(30, 100, 1024);
    let second = normal(31, 200, 1024);
    {
        let mut q = CfsRunqueue::new();
        assert!(q.enqueue(Arc::clone(&first)));
        assert!(q.enqueue(Arc::clone(&second)));
    }
    for task in [&first, &second] {
        assert!(!task.on_class_rq.load(Ordering::Acquire));
        assert!(!task.sched.se.on_rq.load(Ordering::Acquire));
    }
    let mut q = CfsRunqueue::new();
    assert!(q.enqueue(Arc::clone(&first)));
    assert_eq!(q.pick_leftmost().unwrap().tid, first.tid);
}

#[test]
fn cfs_order_crosses_vruntime_wrap_in_signed_horizon_order() {
    let mut q = CfsRunqueue::new();
    assert!(q.enqueue(normal(40, u64::MAX - 1, 1024)));
    assert!(q.enqueue(normal(41, 0, 1024)));
    assert!(q.enqueue(normal(42, 2, 1024)));
    assert_eq!(q.pick_leftmost().unwrap().tid, 40);
    assert_eq!(q.pick_leftmost().unwrap().tid, 41);
    assert_eq!(q.pick_leftmost().unwrap().tid, 42);
}

#[test]
fn cfs_ordered_insert_and_erase_remain_logarithmically_balanced() {
    let mut q = CfsRunqueue::new();
    let tasks: alloc::vec::Vec<_> = (1..=255)
        .map(|tid| normal(tid, tid as u64, 1024)).collect();
    for task in &tasks { assert!(q.enqueue(Arc::clone(task))); }
    assert!(q.root_height_for_test() <= 8,
        "ordered insertion degraded the intrusive tree below AVL balance");
    for task in tasks.iter().step_by(2) {
        assert_eq!(q.remove(task).unwrap().tid, task.tid);
    }
    assert!(q.root_height_for_test() <= 8);
    for tid in (2..=254).step_by(2) { assert_eq!(q.pick_leftmost().unwrap().tid, tid); }
    assert!(!q.has_runnable());
}

#[test]
fn deadline_task_cannot_alias_or_unlink_from_two_class_queues() {
    let task = deadline(500, 50);
    let mut owner = DlRunqueue::new();
    let mut contender = DlRunqueue::new();
    assert!(owner.enqueue(Arc::clone(&task)));
    assert!(!contender.enqueue(Arc::clone(&task)));
    assert!(contender.remove(&task).is_none());
    assert_eq!(owner.nr_running(), 1);
    assert_eq!(owner.remove(&task).unwrap().tid, task.tid);
    assert!(contender.enqueue(Arc::clone(&task)));
    assert_eq!(contender.pick_earliest().unwrap().tid, task.tid);
}

#[test]
fn deadline_ordered_insert_and_direct_erase_remain_balanced() {
    let mut q = DlRunqueue::new();
    let tasks: alloc::vec::Vec<_> = (1..=255)
        .map(|tid| deadline(600 + tid, tid as u64)).collect();
    for task in &tasks { assert!(q.enqueue(Arc::clone(task))); }
    assert!(q.root_height_for_test() <= 8);
    for task in tasks.iter().step_by(2) {
        assert_eq!(q.remove(task).unwrap().tid, task.tid);
    }
    assert!(q.root_height_for_test() <= 8);
    for task in tasks.iter().skip(1).step_by(2) {
        assert_eq!(q.pick_earliest().unwrap().tid, task.tid);
    }
}
