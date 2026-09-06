use super::*;

#[test]
fn selecting_group_member_does_not_charge_unexecuted_slice() {
    let root = crate::task_group::root();
    let (group, created) = crate::task_group::register(981_201, &root, 1024);
    assert!(created);
    let task = Arc::new(Task::new(981_201, "io-burst", SchedClass::Normal { weight: 1024 }));
    task.sched.store_group_id(group.id());
    let mut rq = CfsRunqueue::new();
    rq.online_group(&group);
    assert!(rq.enqueue(task));
    let before = rq.children[&group.id()].vruntime;
    let _selected = rq.pick_leftmost().unwrap();
    let after = rq.children[&group.id()].vruntime;
    rq.offline_group(group.id());
    crate::task_group::unregister(group.id());
    assert_eq!(after, before, "selection charged runtime before execution");
}

#[test]
fn live_accounting_charges_short_burst_to_each_ancestor_by_shares() {
    const START: u64 = 1_000_000;
    const BURST: u64 = 100_000;
    let root = crate::task_group::root();
    let (parent, created) = crate::task_group::register(981_202, &root, 2048);
    assert!(created);
    let (leaf, created) = crate::task_group::register(981_203, &parent, 1024);
    assert!(created);
    let task = Arc::new(Task::new(981_202, "short-burst", SchedClass::Normal { weight: 1024 }));
    task.sched.store_group_id(leaf.id());
    task.sched.se.exec_start.store(START, Ordering::Release);
    let idle = Arc::new(Task::new(981_204, "idle", SchedClass::Idle));
    let mut inner = crate::RunqueueInner::new(0, idle);
    assert!(inner.enqueue(Arc::clone(&task)));
    let selected = inner.pick_next_task();
    assert_eq!(selected.tid, task.tid);
    crate::live::schedule::settle_running_for_change(&selected, &mut inner, START + BURST);
    let parent_runtime = inner.cfs.children[&parent.id()].vruntime;
    let leaf_runtime = inner.cfs.children[&parent.id()].rq.children[&leaf.id()].vruntime;
    crate::live::schedule::settle_running_for_change(&selected, &mut inner, START + BURST);
    let repeated = inner.cfs.children[&parent.id()].vruntime;
    inner.cfs.offline_group(leaf.id());
    inner.cfs.offline_group(parent.id());
    crate::task_group::unregister(leaf.id());
    crate::task_group::unregister(parent.id());
    assert_eq!(parent_runtime, BURST / 2, "parent charged a full slice or ignored shares");
    assert_eq!(leaf_runtime, BURST, "leaf charged a full slice instead of execution");
    assert_eq!(repeated, parent_runtime, "same elapsed interval charged twice");
}
