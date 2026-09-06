use super::*;

fn task(tid: u32, vruntime: u64, deadline: u64) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "candidate", SchedClass::Normal { weight: 1024 }));
    task.sched.se.vruntime.store(vruntime, Ordering::Release);
    task.sched.se.deadline.store(deadline, Ordering::Release);
    task
}

fn enqueue(rq: &mut CfsRunqueue, task: &Arc<Task>, deadline: u64) {
    assert!(rq.enqueue(Arc::clone(task)));
    task.sched.se.deadline.store(deadline, Ordering::Release);
}

#[test]
fn eligible_earlier_deadline_wins_despite_larger_vruntime() {
    let current = task(986_001, 0, 30);
    let wake = task(986_002, 10, 20);
    let peer = task(986_003, 20, 40);
    let mut rq = CfsRunqueue::new();
    enqueue(&mut rq, &wake, 20);
    enqueue(&mut rq, &peer, 40);
    assert!(rq.wakeup_preempts(&current, &wake));
}

#[test]
fn ineligible_wake_cannot_preempt_even_with_earliest_deadline() {
    let current = task(986_011, 0, 30);
    let wake = task(986_012, 20, 1);
    let mut rq = CfsRunqueue::new();
    enqueue(&mut rq, &wake, 1);
    assert!(!rq.wakeup_preempts(&current, &wake));
}

#[test]
fn another_eligible_entity_wins_over_the_wakee() {
    let current = task(986_021, 10, 30);
    let wake = task(986_022, 10, 20);
    let peer = task(986_023, 10, 5);
    let mut rq = CfsRunqueue::new();
    enqueue(&mut rq, &wake, 20);
    enqueue(&mut rq, &peer, 5);
    assert!(!rq.wakeup_preempts(&current, &wake));
}

#[test]
fn running_group_with_queued_members_is_counted_once() {
    let root = crate::task_group::root();
    let groups: alloc::vec::Vec<_> = (986_031..=986_033).map(|id| {
        let (group, created) = crate::task_group::register(id, &root, 1024);
        assert!(created);
        group
    }).collect();
    let current = task(986_034, 1000, 2000);
    current.sched.store_group_id(groups[0].id());
    let mut rq = CfsRunqueue::new();
    for group in &groups { rq.online_group(group); }
    let members: alloc::vec::Vec<_> = groups.iter().enumerate().map(|(index, group)| {
        let member = task(986_035 + index as u32, 0, 1);
        member.sched.store_group_id(group.id());
        enqueue(&mut rq, &member, 1);
        member
    }).collect();
    for (index, group) in groups.iter().enumerate() {
        let entity = rq.children.get_mut(&group.id()).unwrap();
        entity.vruntime = 10 + index as u64 * 5;
        entity.deadline = [30, 5, 40][index];
    }
    let preempt = rq.wakeup_preempts(&current, &members[1]);
    while rq.pick_leftmost().is_some() {}
    for group in &groups {
        rq.offline_group(group.id());
        crate::task_group::unregister(group.id());
    }
    assert!(preempt, "double-counted current group made the wakee ineligible");
}
