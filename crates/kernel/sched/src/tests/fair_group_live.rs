use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::cfs::CfsRunqueue;
use crate::task_group::{self, TaskGroup};
use crate::{RunqueueInner, Task};

use super::common;

fn child(id: u64, parent: &Arc<TaskGroup>, shares: u32) -> Arc<TaskGroup> {
    let (group, created) = task_group::register(id, parent, shares);
    assert!(created, "test task-group identity was already registered");
    group
}

fn member(tid: u32, group: &TaskGroup) -> Arc<Task> {
    let task = common::normal(tid, 0, 1024);
    task.sched.store_group_id(group.id());
    task
}

fn retire(mut rq: CfsRunqueue, groups: &[&TaskGroup]) {
    while rq.pick_leftmost().is_some() {}
    for group in groups { rq.offline_group(group.id()); }
}

#[test]
fn nested_group_entity_descends_to_its_live_child_runqueue() {
    let root = task_group::root();
    let parent = child(932_900, &root, 1024);
    let nested = child(932_901, &parent, 1024);
    let task = member(93_290, &nested);
    let mut rq = CfsRunqueue::new();
    rq.online_group(&parent);
    rq.online_group(&nested);

    assert!(rq.enqueue(Arc::clone(&task)));
    assert_eq!(rq.group_shape_for_test(parent.id()), Some((1, 1)));
    assert_eq!(rq.group_shape_for_test(nested.id()), Some((2, 1)));
    assert_eq!(rq.pick_leftmost().unwrap().tid, task.tid);
    assert_eq!(rq.nr_running(), 0);

    retire(rq, &[&nested, &parent]);
    task_group::unregister(nested.id());
    task_group::unregister(parent.id());
}

#[test]
fn sibling_groups_compete_as_entities_not_as_flat_member_tasks() {
    let root = task_group::root();
    let crowded = child(932_910, &root, 1024);
    let single = child(932_911, &root, 1024);
    let first = member(93_291, &crowded);
    let second = member(93_292, &crowded);
    let peer = member(93_293, &single);
    let mut rq = CfsRunqueue::new();
    rq.online_group(&crowded);
    rq.online_group(&single);
    assert!(rq.enqueue(first));
    assert!(rq.enqueue(second));
    assert!(rq.enqueue(Arc::clone(&peer)));

    let selected = rq.pick_leftmost().unwrap();
    assert_eq!(selected.tid, 93_291);
    rq.account_runtime(&selected, 4_000_000);
    assert_eq!(rq.pick_leftmost().unwrap().tid, peer.tid,
        "a group's second member bypassed an equal sibling group entity");

    retire(rq, &[&single, &crowded]);
    task_group::unregister(single.id());
    task_group::unregister(crowded.id());
}

#[test]
fn live_group_reweight_changes_parent_entity_without_changing_task_nice() {
    let root = task_group::root();
    let light = child(932_920, &root, 1024);
    let boosted = child(932_921, &root, 1024);
    let light_task = member(93_294, &light);
    let boosted_task = member(93_295, &boosted);
    let original_load = boosted_task.sched.se.load.snapshot().weight;
    let mut rq = CfsRunqueue::new();
    rq.online_group(&light);
    rq.online_group(&boosted);
    assert!(rq.enqueue(light_task));
    assert!(rq.enqueue(Arc::clone(&boosted_task)));

    boosted.store_shares(4096);
    rq.reweight_group(&boosted);
    assert_eq!(boosted_task.sched.se.load.snapshot().weight, original_load,
        "cpu.weight rewrote the member task's nice-derived load");
    assert_eq!(rq.pick_leftmost().unwrap().tid, boosted_task.tid,
        "reweighted parent entity did not reach live selection");

    retire(rq, &[&boosted, &light]);
    task_group::unregister(boosted.id());
    task_group::unregister(light.id());
}

#[test]
fn canonical_cgroup_membership_builds_the_live_nested_rq_path() {
    let _serial = common::hosted_global_test_lock();
    let _ = cgroup::realize_tree();
    let parent_name = "ki0329-live-parent";
    let child_name = "ki0329-live-child";
    let parent = cgroup::mkdir_child(cgroup::ROOT_CGROUP, parent_name, 0, 0).unwrap();
    let leaf = cgroup::mkdir_child(parent, child_name, 0, 0).unwrap();
    let task = common::normal(93_296, 0, 1024);
    cgroup::attach_tid_into(leaf, task.tid as u64).unwrap();

    crate::cgroup::sync_task_group(&task);
    assert_eq!(task.sched.group_id(), leaf);
    let mut live = RunqueueInner::new(0, common::idle(93_297));
    assert!(live.enqueue(Arc::clone(&task)));
    assert_eq!(live.cfs.group_shape_for_test(parent), Some((1, 1)));
    assert_eq!(live.cfs.group_shape_for_test(leaf), Some((2, 1)));
    assert_eq!(live.pick_next_task().tid, task.tid);
    assert!(!task.on_class_rq.load(Ordering::Acquire));
    drop(live);

    cgroup::on_exit(task.tid as u64, task.tid as u64);
    cgroup::rmdir_child(parent, child_name).unwrap();
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, parent_name).unwrap();
}
