use super::common::registry_test_lock;
use crate::registry::{self, PidfdAcquireError, PidfdKind};
use crate::task::{SchedClass, Task};
use crate::thread_group::ExitDisposition;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use namespace_identity::{allocate, initial, lookup, NamespaceKind, NamespaceRef};

extern crate std;

fn nested_pid_ns(parent: NamespaceRef) -> NamespaceRef {
    allocate(NamespaceKind::Pid, initial(NamespaceKind::User), Some(parent)).unwrap()
}

fn task(tid: u32, ns: &NamespaceRef, numbers: &[u32], vtgid: u32) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "pidfd", SchedClass::Normal { weight: 1024 }));
    assert!(task.replace_namespace(ns.clone()).is_ok());
    task.vtid.store(numbers[0], Ordering::Release);
    task.vtgid.store(vtgid, Ordering::Release);
    task.configure_pid_mappings(numbers).unwrap();
    task
}

fn thread(tid: u32, ns: &NamespaceRef, numbers: &[u32], leader: &Arc<Task>) -> Arc<Task> {
    let mut task = Task::new(tid, "pidfd-thread", SchedClass::Normal { weight: 1024 });
    task.tgid.store(leader.tid, Ordering::Release);
    assert!(task.replace_namespace(ns.clone()).is_ok());
    task.vtid.store(numbers[0], Ordering::Release);
    task.vtgid.store(leader.vtgid.load(Ordering::Acquire), Ordering::Release);
    task.join_thread_group(Arc::clone(&leader.thread_group));
    task.thread_group.commit_member();
    let task = Arc::new(task);
    task.configure_pid_mappings(numbers).unwrap();
    task
}

#[test]
fn zombie_before_open_acquires_retained_identity() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let ns = initial(NamespaceKind::Pid);
    let leader = task(100, &ns, &[50], 50);
    registry::insert(&leader);
    leader.mark_done();

    let identity = registry::acquire_pidfd_in_namespace(&ns, 50, PidfdKind::Process).unwrap();
    assert!(Arc::ptr_eq(&identity, &leader.pid));
}

#[test]
fn acquire_before_reap_retains_identity_but_not_task_link() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let ns = initial(NamespaceKind::Pid);
    let leader = task(110, &ns, &[51], 51);
    registry::insert(&leader);
    let identity = registry::acquire_pidfd_in_namespace(&ns, 51, PidfdKind::Process).unwrap();

    registry::mark_reaped(&leader);
    assert!(Arc::ptr_eq(&identity, &leader.pid));
    assert!(identity.task().is_none());
    assert!(registry::live_tids().is_empty(),
        "release_task removes a pidfd-pinned task from the process table");
    assert!(matches!(
        registry::acquire_pidfd_in_namespace(&ns, 51, PidfdKind::Process),
        Err(PidfdAcquireError::NotFound)
    ));
}

#[test]
fn reap_before_acquire_is_not_found() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let ns = initial(NamespaceKind::Pid);
    let leader = task(120, &ns, &[52], 52);
    registry::insert(&leader);
    registry::mark_reaped(&leader);

    assert!(matches!(
        registry::acquire_pidfd_in_namespace(&ns, 52, PidfdKind::Process),
        Err(PidfdAcquireError::NotFound)
    ));
}

#[test]
fn visible_pid_reuse_selects_replacement_identity() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let ns = initial(NamespaceKind::Pid);
    let old = task(130, &ns, &[53], 53);
    registry::insert(&old);
    registry::mark_reaped(&old);
    let replacement = task(230, &ns, &[53], 53);
    registry::insert(&replacement);

    let identity = registry::acquire_pidfd_in_namespace(&ns, 53, PidfdKind::Process).unwrap();
    assert!(Arc::ptr_eq(&identity, &replacement.pid));
    assert!(!Arc::ptr_eq(&identity, &old.pid));
}

#[test]
fn process_and_thread_selection_ignore_registry_order() {
    let _guard = registry_test_lock();
    let ns = nested_pid_ns(initial(NamespaceKind::Pid));
    let other_owner = nested_pid_ns(initial(NamespaceKind::Pid));
    let leader = task(140, &ns, &[60, 160], 60);
    let member = thread(141, &ns, &[61, 161], &leader);
    let other_ns = task(240, &other_owner, &[60, 260], 60);
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
        let process = registry::acquire_pidfd_in_namespace(&ns, 60, PidfdKind::Process).unwrap();
        let exact_thread = registry::acquire_pidfd_in_namespace(&ns, 61, PidfdKind::Thread).unwrap();
        assert!(Arc::ptr_eq(&process, &leader.pid));
        assert!(Arc::ptr_eq(&exact_thread, &member.pid));
        assert!(matches!(
            registry::acquire_pidfd_in_namespace(&ns, 61, PidfdKind::Process),
            Err(PidfdAcquireError::NotLeader)
        ));
    }
}

#[test]
fn early_leader_waitability_and_readiness_wait_for_final_thread() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let ns = initial(NamespaceKind::Pid);
    let leader = task(150, &ns, &[70], 70);
    let member = thread(151, &ns, &[71], &leader);
    registry::insert(&leader);
    registry::insert(&member);
    let process = registry::acquire_pidfd_in_namespace(&ns, 70, PidfdKind::Process).unwrap();
    let exact_thread = registry::acquire_pidfd_in_namespace(&ns, 71, PidfdKind::Thread).unwrap();

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
    let ns = initial(NamespaceKind::Pid);
    let old_leader = task(160, &ns, &[72], 72);
    let old_member = thread(161, &ns, &[73], &old_leader);
    let replacement = task(160, &ns, &[74], 74);
    assert!(!Arc::ptr_eq(&old_leader.thread_group, &replacement.thread_group));
    assert!(Arc::ptr_eq(&old_leader.thread_group, &old_member.thread_group));
}

#[test]
fn concurrent_leader_and_final_thread_retirement_cannot_lose_leader() {
    let ns = initial(NamespaceKind::Pid);
    let leader = task(170, &ns, &[75], 75);
    let member = thread(171, &ns, &[76], &leader);
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
    let ns = initial(NamespaceKind::Pid);
    let leader = task(180, &ns, &[77], 77);
    let mut failed = Task::new(181, "failed-clone", SchedClass::Normal { weight: 1024 });
    failed.join_thread_group(Arc::clone(&leader.thread_group));
    let _failed = Arc::new(failed);
    leader.mark_done();
    assert!(matches!(
        leader.thread_group.finish_exit(Arc::clone(&leader)),
        ExitDisposition::WaitableLeader(_)
    ));
}

#[test]
fn thread_group_reports_exact_live_singleton_state() {
    let ns = initial(NamespaceKind::Pid);
    let leader = task(182, &ns, &[78], 78);
    assert!(leader.thread_group.is_single_member());
    let member = thread(183, &ns, &[79], &leader);
    assert!(!leader.thread_group.is_single_member());
    member.mark_done();
    assert!(matches!(member.thread_group.finish_exit(Arc::clone(&member)),
        ExitDisposition::ReleasedThread));
    assert!(leader.thread_group.is_single_member());
}

#[test]
fn nested_child_is_visible_as_one_inside_and_parent_number_outside() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let parent = initial(NamespaceKind::Pid);
    let child_ns = nested_pid_ns(parent.clone());
    let child = task(190, &child_ns, &[1, 81], 1);
    registry::insert(&child);

    assert!(Arc::ptr_eq(
        &registry::lookup_in_namespace(&child_ns, 1).unwrap(), &child));
    assert!(Arc::ptr_eq(
        &registry::lookup_in_namespace(&parent, 81).unwrap(), &child));
}

#[test]
fn clone_new_pidns_maps_one_inside_and_allocated_number_through_ancestors() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let outer = initial(NamespaceKind::Pid);
    let parent = nested_pid_ns(outer.clone());
    let inner = nested_pid_ns(parent.clone());
    let child = task(193, &inner, &[1, 84, 84], 1);

    assert!(registry::lookup(child.tid).is_none(), "mapping configuration cannot publish task");
    registry::insert(&child);
    assert!(Arc::ptr_eq(&registry::lookup_in_namespace(&inner, 1).unwrap(), &child));
    assert!(Arc::ptr_eq(&registry::lookup_in_namespace(&parent, 84).unwrap(), &child));
    assert!(Arc::ptr_eq(&registry::lookup_in_namespace(&outer, 84).unwrap(), &child));
}

#[test]
fn clone_existing_pidns_maps_allocated_number_through_all_ancestors() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let outer = initial(NamespaceKind::Pid);
    let parent = nested_pid_ns(outer.clone());
    let current = nested_pid_ns(parent.clone());
    let child = task(194, &current, &[85, 85, 85], 85);
    registry::insert(&child);

    for namespace in [&current, &parent, &outer] {
        assert!(Arc::ptr_eq(
            &registry::lookup_in_namespace(namespace, 85).unwrap(), &child));
    }
}

#[test]
fn failed_clone_pid_mapping_does_not_publish_registry_member() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let outer = initial(NamespaceKind::Pid);
    let parent = nested_pid_ns(outer.clone());
    let inner = nested_pid_ns(parent.clone());
    let child = Arc::new(Task::new(195, "failed-clone", SchedClass::Normal { weight: 1024 }));
    assert!(child.replace_namespace(inner.clone()).is_ok());
    child.vtid.store(1, Ordering::Release);

    assert!(child.configure_pid_mappings(&[1, 86]).is_err());
    assert!(registry::lookup(child.tid).is_none());
    assert!(registry::lookup_in_namespace(&inner, 1).is_none());
    assert!(registry::lookup_in_namespace(&parent, 86).is_none());
    assert!(registry::lookup_in_namespace(&outer, 86).is_none());
}

#[test]
fn pidfd_zombie_lookup_uses_pinned_caller_namespace_without_retaining_it() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let parent = initial(NamespaceKind::Pid);
    let ns = nested_pid_ns(parent);
    let id = ns.id();
    let target = task(191, &ns, &[42, 82], 42);
    registry::insert(&target);
    target.mark_done();
    target.release_namespaces();

    let pidfd = registry::acquire_pidfd_in_namespace(&ns, 42, PidfdKind::Process).unwrap();
    assert!(Arc::ptr_eq(&pidfd, &target.pid));
    registry::clear_for_tests();
    drop(target);
    drop(ns);
    assert!(lookup(NamespaceKind::Pid, id).is_none(), "pidfd must retain only weak mappings");
    let replacement = nested_pid_ns(initial(NamespaceKind::Pid));
    assert_eq!(pidfd.visible_tid(&replacement), None);
}

#[test]
fn dead_namespace_owner_cannot_retarget_exact_mapping() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let ns = nested_pid_ns(initial(NamespaceKind::Pid));
    let stale_id = ns.id();
    let target = task(192, &ns, &[43, 83], 43);
    registry::insert(&target);
    target.release_namespaces();
    drop(ns);

    assert!(lookup(NamespaceKind::Pid, stale_id).is_none());
    let replacement = nested_pid_ns(initial(NamespaceKind::Pid));
    assert!(registry::acquire_pidfd_in_namespace(&replacement, 43, PidfdKind::Process).is_err());
}
