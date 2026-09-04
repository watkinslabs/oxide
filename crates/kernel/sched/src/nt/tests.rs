use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::*;
use crate::{SchedClass, Task, TaskState};

fn sleeping(tid: u32, level: u8) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "nt-policy",
        SchedClass::NtFixed { level, quantum: 6 }));
    task.set_state(TaskState::Sleeping);
    task
}

fn pair() -> (Arc<crate::thread_group::ThreadGroup>, Arc<Task>, Arc<Task>) {
    let leader = sleeping(33_001, 8);
    let group = Arc::clone(&leader.thread_group);
    group.register_nt_sched_member(&leader);
    let mut sibling = Task::new(33_002, "nt-policy",
        SchedClass::NtFixed { level: 8, quantum: 6 });
    sibling.join_thread_group(Arc::clone(&group));
    sibling.set_state(TaskState::Sleeping);
    let sibling = Arc::new(sibling);
    group.register_nt_sched_member(&sibling);
    (group, leader, sibling)
}

#[test]
fn class_relative_table_is_exhaustive() {
    let classes = [NtPriorityClass::Idle, NtPriorityClass::BelowNormal,
        NtPriorityClass::Normal, NtPriorityClass::AboveNormal,
        NtPriorityClass::High, NtPriorityClass::Realtime];
    let relative = [NtRelativePriority::Idle, NtRelativePriority::Lowest,
        NtRelativePriority::BelowNormal, NtRelativePriority::Normal,
        NtRelativePriority::AboveNormal, NtRelativePriority::Highest,
        NtRelativePriority::TimeCritical];
    let expected = [[1, 2, 3, 4, 5, 6, 15], [1, 4, 5, 6, 7, 8, 15],
        [1, 6, 7, 8, 9, 10, 15], [1, 8, 9, 10, 11, 12, 15],
        [1, 11, 12, 13, 14, 15, 15], [16, 22, 23, 24, 25, 26, 31]];
    for (row, class) in classes.into_iter().enumerate() {
        for (column, priority) in relative.into_iter().enumerate() {
            assert_eq!(class_relative_priority(class, priority), expected[row][column]);
        }
    }
    let mut torn = expected;
    torn[2][4] ^= 1;
    assert!(classes.into_iter().enumerate().any(|(row, class)|
        relative.into_iter().enumerate().any(|(column, priority)|
            class_relative_priority(class, priority) != torn[row][column])),
        "positive control failed to detect a torn priority table");
}

#[test]
fn quantum_policy_tables_and_idle_override_are_exact() {
    let cases = [(NtQuantumPolicy::FixedShort, [18, 18, 18]),
        (NtQuantumPolicy::FixedLong, [36, 36, 36]),
        (NtQuantumPolicy::VariableShort, [6, 12, 18]),
        (NtQuantumPolicy::VariableLong, [12, 24, 36])];
    for (policy, expected) in cases {
        for separation in 0..=2 {
            assert_eq!(policy.quantum(separation, false), expected[separation as usize]);
            assert_eq!(policy.quantum(separation, true), 6);
        }
    }
    let mut torn = [6, 12, 18];
    torn[1] += 1;
    assert!((0..=2).any(|i| NtQuantumPolicy::VariableShort.quantum(i, false)
        != torn[i as usize]), "positive control failed to detect a torn quantum table");
}

#[test]
fn variable_boost_consumes_quantum_then_decays_to_base() {
    let task = sleeping(33_010, 8);
    apply_nt_thread(&task, NtThreadSchedRequest::Boost { increment: 10 }).unwrap();
    let boosted = task.sched.nt_snapshot();
    assert_eq!((boosted.dynamic_priority, boosted.priority_decrement,
        boosted.quantum_remaining), (11, 3, 5));
    for _ in 0..4 { assert!(!tick_unlocked(&task).expired); }
    let expired = tick_unlocked(&task);
    assert!(expired.expired && expired.priority_changed);
    let decayed = task.sched.nt_snapshot();
    assert_eq!((decayed.dynamic_priority, decayed.priority_decrement,
        decayed.quantum_remaining), (8, 0, 6));

    let mut torn = boosted;
    torn.priority_decrement = 0;
    let mut torn_outcome = NtTickOutcome { expired: false, priority_changed: false };
    for _ in 0..5 { (torn, torn_outcome) = super::tick(torn); }
    assert!(torn_outcome.expired);
    assert_ne!(torn.dynamic_priority, decayed.dynamic_priority,
        "positive control no longer proves decrement-driven decay");
}

#[test]
fn realtime_and_boost_disabled_threads_never_dynamic_boost() {
    let variable = sleeping(33_011, 8);
    apply_nt_thread(&variable,
        NtThreadSchedRequest::PriorityBoost { disabled: true }).unwrap();
    apply_nt_thread(&variable, NtThreadSchedRequest::Boost { increment: 12 }).unwrap();
    assert_eq!(variable.sched.nt_snapshot().dynamic_priority, 8);

    let realtime = sleeping(33_012, 24);
    apply_nt_thread(&realtime,
        NtThreadSchedRequest::Priority { priority: 24, may_increase: true }).unwrap();
    apply_nt_thread(&realtime, NtThreadSchedRequest::Boost { increment: 31 }).unwrap();
    assert_eq!(realtime.sched.nt_snapshot().dynamic_priority, 24);
}

#[test]
fn process_class_and_boost_updates_cover_every_member() {
    let (group, leader, sibling) = pair();
    apply_nt_process(&group, NtProcessSchedRequest::PriorityClass {
        class: NtPriorityClass::High, foreground: None, may_increase: true }).unwrap();
    for task in [&leader, &sibling] {
        let state = task.sched.nt_snapshot();
        assert_eq!((state.base_priority, state.dynamic_priority), (13, 13));
    }
    apply_nt_process(&group,
        NtProcessSchedRequest::PriorityBoost { disabled: true }).unwrap();
    assert!(leader.sched.nt_snapshot().boost_disabled);
    assert!(sibling.sched.nt_snapshot().boost_disabled);
    assert_eq!(group.nt_sched_config().class, NtPriorityClass::High);
}

#[test]
fn rejected_process_request_rolls_back_config_and_members() {
    let (group, leader, sibling) = pair();
    let before_config = group.nt_sched_config();
    let before = [leader.sched.nt_snapshot(), sibling.sched.nt_snapshot()];
    assert_eq!(apply_nt_process(&group, NtProcessSchedRequest::Foreground {
        foreground: true, separation: 3 }), Err(NtSchedError::InvalidPriority));
    assert_eq!(group.nt_sched_config(), before_config);
    assert_eq!([leader.sched.nt_snapshot(), sibling.sched.nt_snapshot()], before);

    assert!(apply_nt_process(&group, NtProcessSchedRequest::PriorityClass {
        class: NtPriorityClass::High, foreground: None, may_increase: true }).is_ok(),
        "positive control: valid transaction did not mutate the process");
    assert_ne!(leader.sched.nt_snapshot(), before[0]);
}

#[test]
fn thread_base_priority_preserves_relative_state_and_direct_priority_does_not_replace_it() {
    let task = sleeping(33_020, 8);
    apply_nt_thread(&task, NtThreadSchedRequest::BasePriority(2)).unwrap();
    let base = task.sched.nt_snapshot();
    assert_eq!((base.base_priority, base.dynamic_priority, base.relative_priority), (10, 10, 2));
    apply_nt_thread(&task, NtThreadSchedRequest::Priority {
        priority: 12, may_increase: false }).unwrap();
    let direct = task.sched.nt_snapshot();
    assert_eq!((direct.base_priority, direct.dynamic_priority, direct.relative_priority),
        (10, 12, 2));
    assert_eq!(apply_nt_thread(&task, NtThreadSchedRequest::Priority {
        priority: 16, may_increase: false }), Err(NtSchedError::PrivilegeNotHeld));
    assert_eq!(task.sched.nt_snapshot(), direct);
}

#[test]
fn new_native_thread_uses_process_normal_not_creator_dynamic_priority() {
    let (group, leader, _) = pair();
    apply_nt_thread(&leader, NtThreadSchedRequest::Priority {
        priority: 12, may_increase: false }).unwrap();
    apply_nt_process(&group,
        NtProcessSchedRequest::PriorityBoost { disabled: true }).unwrap();
    let mut child = Task::new(33_021, "new-nt-thread",
        SchedClass::NtFixed { level: 3, quantum: 1 });
    child.join_thread_group(group);
    initialize_new_thread(&child);
    let state = child.sched.nt_snapshot();
    assert_eq!((state.base_priority, state.dynamic_priority, state.relative_priority), (8, 8, 0));
    assert!(state.boost_disabled);
    assert_ne!(state.dynamic_priority, leader.sched.nt_snapshot().dynamic_priority,
        "positive control: child accidentally inherited creator dynamic priority");
}

#[test]
fn process_base_change_preserves_a_stronger_pi_effective_priority() {
    let (group, leader, _) = pair();
    leader.set_sched_class(SchedClass::NtFixed { level: 20, quantum: 6 });
    apply_nt_process(&group, NtProcessSchedRequest::PriorityClass {
        class: NtPriorityClass::BelowNormal, foreground: None, may_increase: false }).unwrap();
    assert!(matches!(leader.normal_sched_class(),
        SchedClass::NtFixed { level: 6, .. }));
    assert!(matches!(leader.sched_class(), SchedClass::NtFixed { level: 20, .. }),
        "process mutation overwrote a stronger PI donor");
    leader.restore_normal_sched_class();
    assert!(matches!(leader.sched_class(), SchedClass::NtFixed { level: 6, .. }),
        "positive control: removing PI did not reveal the process-updated base");
}

struct InstalledGlobal;
impl InstalledGlobal {
    fn new() -> Self {
        let idle = Arc::new(Task::new(33_099, "idle", SchedClass::Idle));
        unsafe { crate::live::runqueue::install_global(
            crate::live::runqueue::Runqueue::new(0, idle)); }
        Self
    }
}
impl Drop for InstalledGlobal {
    fn drop(&mut self) { let _ = unsafe { crate::live::runqueue::uninstall_global() }; }
}

#[test]
fn process_priority_transaction_rekeys_real_queued_members() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    let _installed = InstalledGlobal::new();
    let (group, leader, sibling) = pair();
    leader.set_state(TaskState::Runnable);
    sibling.set_state(TaskState::Runnable);
    let outsider = Arc::new(Task::new(33_003, "outsider",
        SchedClass::NtFixed { level: 10, quantum: 6 }));
    let rq = crate::live::runqueue::global().unwrap();
    {
        let mut inner = rq.inner.lock();
        assert!(inner.enqueue(Arc::clone(&leader)));
        assert!(inner.enqueue(Arc::clone(&sibling)));
        assert!(inner.enqueue(Arc::clone(&outsider)));
        rq.publish_nr_running(inner.nr_running());
    }
    apply_nt_process(&group, NtProcessSchedRequest::PriorityClass {
        class: NtPriorityClass::High, foreground: None, may_increase: true }).unwrap();
    assert!(leader.on_rq.is_queued(Ordering::Acquire));
    assert!(sibling.on_class_rq.load(Ordering::Acquire));
    let mut inner = rq.inner.lock();
    assert_eq!(inner.nr_running(), 3);
    let first = inner.pick_next_task();
    let second = inner.pick_next_task();
    assert!([leader.tid, sibling.tid].contains(&first.tid));
    assert!([leader.tid, sibling.tid].contains(&second.tid));
    assert_eq!(inner.pick_next_task().tid, outsider.tid,
        "positive control: unchanged level-10 task outranked promoted members");
}
