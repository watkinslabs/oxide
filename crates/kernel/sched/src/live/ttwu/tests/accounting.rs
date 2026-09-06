use super::*;

#[test]
fn direct_placement_accounts_elapsed_cpu_before_requesting_preemption() {
    const CPU: u32 = 47;
    const START: u64 = 1_000_000;
    const NOW: u64 = 5_000_000;
    let cpus = Cpus::new(&[CPU]);
    let rq = cpus.get(CPU).unwrap();
    let current = fair_task(984_701, SCHED_NORMAL, 10_000_000);
    make_current(rq, &current, CPU);
    current.sched.se.exec_start.store(START, Ordering::Release);
    let wakee = settled_sleeper(984_702, CPU);
    wakee.sched.se.vruntime.store(12_000_000, Ordering::Release);
    assert!(wakee.claim_wake());
    assert!(!crate::preempt::need_resched_on(CPU as usize));
    {
        let _pi = wakee.pi_lock.lock_irqsave::<RqIrq>();
        place_runnable_locked_with_clock(&|c| cpus.get(c), CPU,
            Arc::clone(&wakee), false, &|c| c == CPU, &mut |_, _| {}, || NOW);
    }
    assert!(wakee.on_class_rq.load(Ordering::Acquire), "wake was not activated");
    assert_eq!(current.sched.se.sum_exec_runtime.load(Ordering::Acquire), NOW - START);
    assert!(crate::preempt::need_resched_on(CPU as usize), "live placement omitted reschedule");
}

fn cross_group_wake(cpu: u32, leaf_shift: u64, deferred: bool) -> bool {
    let root = crate::task_group::root();
    let base = 985_000 + cpu as u64 * 10;
    let (parent, created) = crate::task_group::register(base, &root, 1024);
    assert!(created);
    let (running_group, created) = crate::task_group::register(base + 1, &parent, 1024);
    assert!(created);
    let (wake_group, created) = crate::task_group::register(base + 2, &parent, 1024);
    assert!(created);
    let cpus = Cpus::new(&[cpu]);
    let rq = cpus.get(cpu).unwrap();
    let current = fair_task(base as u32, SCHED_NORMAL, 10_000_000);
    current.sched.store_group_id(running_group.id());
    make_current(rq, &current, cpu);
    rq.inner.lock().cfs.account_runtime(&current, 4_000_000);
    let wakee = settled_sleeper(base as u32 + 1, cpu);
    wakee.sched.store_group_id(wake_group.id());
    wakee.sched.se.vruntime.store(leaf_shift, Ordering::Release);
    assert!(wakee.claim_wake());
    if deferred {
        wake_list_push_selected(cpu, Arc::clone(&wakee));
        assert!(sched_ttwu_pending(cpu, Arc::as_ptr(&current) as *mut Task, rq));
    } else {
        place_runnable_with(&|c| cpus.get(c), cpu, Arc::clone(&wakee), false);
    }
    assert!(wakee.on_class_rq.load(Ordering::Acquire));
    let requested = crate::preempt::need_resched_on(cpu as usize);
    {
        let mut inner = rq.inner.lock();
        let _ = inner.remove(wakee.tid);
        inner.cfs.offline_group(wake_group.id());
        inner.cfs.offline_group(running_group.id());
        inner.cfs.offline_group(parent.id());
    }
    crate::task_group::unregister(wake_group.id());
    crate::task_group::unregister(running_group.id());
    crate::task_group::unregister(parent.id());
    requested
}

#[test]
fn direct_cross_group_wake_is_invariant_under_leaf_clock_shift() {
    let before = cross_group_wake(48, 0, false);
    let shifted = cross_group_wake(49, 100_000_000, false);
    assert!(before, "eligible sibling group should preempt the indebted running group");
    assert_eq!(shifted, before, "unrelated leaf clock changed live wake preemption");
}

#[test]
fn deferred_cross_group_wake_uses_ancestor_clock() {
    assert!(cross_group_wake(58, 100_000_000, true),
        "deferred activation compared unrelated leaf clocks");
}
