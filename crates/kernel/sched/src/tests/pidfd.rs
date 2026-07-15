use super::common::registry_test_lock;
use crate::registry::{self, PidfdAcquireError, PidfdKind};
use crate::task::{SchedClass, Task};
use crate::thread_group::ExitDisposition;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

extern crate std;

fn task(tid: u32, ns: u64, vtid: u32, vtgid: u32) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "pidfd", SchedClass::Normal { weight: 1024 }));
    task.pid_ns.store(ns, Ordering::Release);
    task.vtid.store(vtid, Ordering::Release);
    task.vtgid.store(vtgid, Ordering::Release);
    task
}

fn thread(tid: u32, ns: u64, vtid: u32, leader: &Arc<Task>) -> Arc<Task> {
    let mut task = Task::new(tid, "pidfd-thread", SchedClass::Normal { weight: 1024 });
    task.tgid.store(leader.tid, Ordering::Release);
    task.pid_ns.store(ns, Ordering::Release);
    task.vtid.store(vtid, Ordering::Release);
    task.vtgid.store(leader.vtgid.load(Ordering::Acquire), Ordering::Release);
    task.join_thread_group(Arc::clone(&leader.thread_group));
    task.thread_group.commit_member();
    Arc::new(task)
}

#[test]
fn zombie_before_open_acquires_retained_identity() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let leader = task(100, 7, 50, 50);
    registry::insert(&leader);
    leader.mark_done();

    let identity = registry::acquire_pidfd(7, 50, PidfdKind::Process).unwrap();
    assert!(Arc::ptr_eq(&identity, &leader.pid));
}

#[test]
fn acquire_before_reap_retains_identity_but_not_task_link() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let leader = task(110, 7, 51, 51);
    registry::insert(&leader);
    let identity = registry::acquire_pidfd(7, 51, PidfdKind::Process).unwrap();

    registry::mark_reaped(&leader);
    assert!(Arc::ptr_eq(&identity, &leader.pid));
    assert!(identity.task().is_none());
    assert!(matches!(
        registry::acquire_pidfd(7, 51, PidfdKind::Process),
        Err(PidfdAcquireError::NotFound)
    ));
}

#[test]
fn reap_before_acquire_is_not_found() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let leader = task(120, 7, 52, 52);
    registry::insert(&leader);
    registry::mark_reaped(&leader);

    assert!(matches!(
        registry::acquire_pidfd(7, 52, PidfdKind::Process),
        Err(PidfdAcquireError::NotFound)
    ));
}

#[test]
fn visible_pid_reuse_selects_replacement_identity() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let old = task(130, 7, 53, 53);
    registry::insert(&old);
    registry::mark_reaped(&old);
    let replacement = task(230, 7, 53, 53);
    registry::insert(&replacement);

    let identity = registry::acquire_pidfd(7, 53, PidfdKind::Process).unwrap();
    assert!(Arc::ptr_eq(&identity, &replacement.pid));
    assert!(!Arc::ptr_eq(&identity, &old.pid));
}

#[test]
fn process_and_thread_selection_ignore_registry_order() {
    let _guard = registry_test_lock();
    let leader = task(140, 9, 60, 60);
    let member = thread(141, 9, 61, &leader);
    let other_ns = task(240, 10, 60, 60);
    for reverse in [false, true] {
        registry::clear_for_tests();
        if reverse {
            registry::insert(&other_ns);
            registry::insert(&member);
            registry::insert(&leader);
        } else {
            registry::insert(&leader);
            registry::insert(&member);
            registry::insert(&other_ns);
        }
        let process = registry::acquire_pidfd(9, 60, PidfdKind::Process).unwrap();
        let exact_thread = registry::acquire_pidfd(9, 61, PidfdKind::Thread).unwrap();
        assert!(Arc::ptr_eq(&process, &leader.pid));
        assert!(Arc::ptr_eq(&exact_thread, &member.pid));
        assert!(matches!(
            registry::acquire_pidfd(9, 61, PidfdKind::Process),
            Err(PidfdAcquireError::NotLeader)
        ));
    }
}

#[test]
fn early_leader_waitability_and_readiness_wait_for_final_thread() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let leader = task(150, 11, 70, 70);
    let member = thread(151, 11, 71, &leader);
    registry::insert(&leader);
    registry::insert(&member);
    let process = registry::acquire_pidfd(11, 70, PidfdKind::Process).unwrap();
    let exact_thread = registry::acquire_pidfd(11, 71, PidfdKind::Thread).unwrap();

    leader.mark_done();
    assert!(!process.exit_ready());
    assert!(matches!(
        leader.thread_group.finish_exit(Arc::clone(&leader)),
        ExitDisposition::DeferredLeader
    ));

    member.mark_done();
    assert!(exact_thread.exit_ready());
    let disposition = member.thread_group.finish_exit(Arc::clone(&member));
    let waitable = match disposition {
        ExitDisposition::WaitableLeader(waitable) => waitable,
        _ => panic!("final thread must release the deferred leader"),
    };
    assert!(Arc::ptr_eq(&waitable, &leader));
    assert!(process.exit_ready());
    assert!(exact_thread.reaped());
}

#[test]
fn numeric_tgid_reuse_cannot_join_retained_group_identity() {
    let old_leader = task(160, 12, 72, 72);
    let old_member = thread(161, 12, 73, &old_leader);
    let replacement = task(160, 12, 74, 74);
    assert!(!Arc::ptr_eq(&old_leader.thread_group, &replacement.thread_group));
    assert!(Arc::ptr_eq(&old_leader.thread_group, &old_member.thread_group));
}

#[test]
fn concurrent_leader_and_final_thread_retirement_cannot_lose_leader() {
    let leader = task(170, 13, 75, 75);
    let member = thread(171, 13, 76, &leader);
    leader.mark_done();
    member.mark_done();
    let leader_group = Arc::clone(&leader.thread_group);
    let member_group = Arc::clone(&member.thread_group);
    let leader_thread = Arc::clone(&leader);
    let member_thread = Arc::clone(&member);

    let retire_leader = std::thread::spawn(move || leader_group.finish_exit(leader_thread));
    let retire_member = std::thread::spawn(move || member_group.finish_exit(member_thread));
    let results = [retire_leader.join().unwrap(), retire_member.join().unwrap()];
    let waitable = results.into_iter().find_map(|result| match result {
        ExitDisposition::WaitableLeader(task) => Some(task),
        _ => None,
    });
    assert!(Arc::ptr_eq(&waitable.expect("one retirement must release leader"), &leader));
    assert!(leader.pid.exit_ready());
}

#[test]
fn uncommitted_clone_member_cannot_block_group_exit() {
    let leader = task(180, 14, 77, 77);
    let mut failed = Task::new(181, "failed-clone", SchedClass::Normal { weight: 1024 });
    failed.join_thread_group(Arc::clone(&leader.thread_group));
    let _failed = Arc::new(failed);
    leader.mark_done();
    assert!(matches!(
        leader.thread_group.finish_exit(Arc::clone(&leader)),
        ExitDisposition::WaitableLeader(_)
    ));
}
