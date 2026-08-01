// Reporting a pid ACROSS a namespace boundary: every number a reader is shown
// is the one the READER's namespace gives the task, over a real three-level
// nest with real registered tasks — not the helper in isolation.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use namespace_identity::{allocate, initial, NamespaceKind, NamespaceRef};

use super::common::registry_test_lock;
use crate::registry;
use crate::task::{SchedClass, Task};

extern crate std;

fn nested(parent: &NamespaceRef) -> NamespaceRef {
    allocate(NamespaceKind::Pid, initial(NamespaceKind::User), Some(parent.clone())).unwrap()
}

/// A registered leader numbered by its own namespace and every ancestor.
fn leader(tid: u32, ns: &NamespaceRef) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "nested", SchedClass::Normal { weight: 1024 }));
    assert!(task.replace_namespace(ns.clone()).is_ok());
    task.tgid.store(tid, Ordering::Release);
    task.alloc_pid_mappings(&[], true).unwrap();
    registry::insert(&task);
    task
}

/// A thread of `leader`, numbered separately at every level the way Linux
/// numbers a thread's own `struct pid`.
fn thread(tid: u32, ns: &NamespaceRef, leader: &Arc<Task>) -> Arc<Task> {
    let mut task = Task::new(tid, "nested-thread", SchedClass::Normal { weight: 1024 });
    task.tgid.store(leader.tid, Ordering::Release);
    assert!(task.replace_namespace(ns.clone()).is_ok());
    task.join_thread_group(Arc::clone(&leader.thread_group));
    task.thread_group.commit_member();
    let task = Arc::new(task);
    task.alloc_pid_mappings(&[], false).unwrap();
    task.vtgid.store(leader.vtgid.load(Ordering::Acquire), Ordering::Release);
    registry::insert(&task);
    task
}

#[test]
fn a_process_reports_a_different_number_at_every_level() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let root = initial(NamespaceKind::Pid);
    let mid = nested(&root);
    let inner = nested(&mid);
    let task = leader(0x2001, &inner);

    let from_inner = registry::tgid_nr_in(&task, &inner).unwrap();
    let from_mid = registry::tgid_nr_in(&task, &mid).unwrap();
    let from_root = registry::tgid_nr_in(&task, &root).unwrap();
    assert_eq!(from_inner, 1, "a namespace's first process is its init");
    assert_eq!(from_mid, 1);
    assert_ne!(from_root, from_mid, "the host must not reuse the container's number");
    // The reader in the INTERMEDIATE namespace sees the intermediate number —
    // not the global one and not the task's own.
    assert_eq!(from_mid, task.pid_nr_ns(&mid));
    assert_ne!(from_mid, from_root);
}

#[test]
fn a_sibling_namespace_can_name_nothing() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let root = initial(NamespaceKind::Pid);
    let mid = nested(&root);
    let inner = nested(&mid);
    let sibling = nested(&mid);
    let task = leader(0x2011, &inner);

    assert_eq!(registry::tgid_nr_in(&task, &sibling), None);
    assert_eq!(task.pid_nr_ns(&sibling), 0);
    assert!(registry::nr_chain_in(&task, &sibling).is_empty());
}

#[test]
fn a_thread_reports_its_own_number_and_its_process_number_per_level() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let root = initial(NamespaceKind::Pid);
    let inner = nested(&root);
    let group = leader(0x2021, &inner);
    let worker = thread(0x2022, &inner, &group);

    // gettid-shaped number vs getpid-shaped number, each per level.
    assert_ne!(registry::vnr_in(&worker, &inner), registry::tgid_nr_in(&worker, &inner));
    assert_eq!(registry::tgid_nr_in(&worker, &inner), registry::tgid_nr_in(&group, &inner));
    assert_eq!(registry::tgid_nr_in(&worker, &root), registry::tgid_nr_in(&group, &root));
    assert_ne!(registry::tgid_nr_in(&worker, &inner), registry::tgid_nr_in(&worker, &root));
}

#[test]
fn the_ns_chain_a_reader_gets_starts_at_its_own_level() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let root = initial(NamespaceKind::Pid);
    let mid = nested(&root);
    let inner = nested(&mid);
    let task = leader(0x2031, &inner);

    let from_root = registry::nr_chain_in(&task, &root);
    let from_mid = registry::nr_chain_in(&task, &mid);
    let from_inner = registry::nr_chain_in(&task, &inner);
    assert_eq!(from_root.len(), 3);
    assert_eq!(from_mid.len(), 2);
    assert_eq!(from_inner.len(), 1);
    // Each shorter chain is the tail of the longer one: the same numbers, seen
    // from further in.
    assert_eq!(&from_root[1..], &from_mid[..]);
    assert_eq!(&from_mid[1..], &from_inner[..]);
    assert_eq!(from_root[0], registry::tgid_nr_in(&task, &root).unwrap());
}

#[test]
fn a_group_is_named_by_the_readers_numbering() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let root = initial(NamespaceKind::Pid);
    let inner = nested(&root);
    let task = leader(0x2041, &inner);
    let own = task.vtgid.load(Ordering::Acquire);
    task.set_pgid(own);

    let inside = registry::group_chain(&inner, own, &inner);
    let outside = registry::group_chain(&inner, own, &root);
    assert_eq!(inside, alloc::vec![own]);
    assert_eq!(outside.len(), 2);
    assert_eq!(outside[0], registry::tgid_nr_in(&task, &root).unwrap());
    assert_ne!(outside[0], own);
}

#[test]
fn a_signal_names_its_sender_in_the_receivers_namespace() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let root = initial(NamespaceKind::Pid);
    let inner = nested(&root);
    let outsider = leader(0x2051, &root);
    let insider = leader(0x2052, &inner);

    // The container's init, seen by a host reader, is the host's number for it.
    let seen_by_host = registry::tgid_nr_seen_by(&insider, &outsider);
    assert_eq!(seen_by_host, registry::tgid_nr_in(&insider, &root).unwrap());
    assert_ne!(seen_by_host, insider.vtgid.load(Ordering::Acquire));
    // The host task, seen from inside the container, has no name at all.
    assert_eq!(registry::tgid_nr_seen_by(&outsider, &insider), 0);
}

#[test]
fn the_number_a_clone_reports_is_the_callers_not_the_childs() {
    let _guard = registry_test_lock();
    registry::clear_for_tests();
    let root = initial(NamespaceKind::Pid);
    let inner = nested(&root);
    let parent = leader(0x2061, &root);
    let child = leader(0x2062, &inner);

    // What `clone` returns to a parent outside the new namespace.
    let reported = child.pid_nr_ns(&parent.namespace_owner(NamespaceKind::Pid).unwrap());
    assert_eq!(reported, registry::tgid_nr_in(&child, &root).unwrap());
    assert_eq!(child.vtgid.load(Ordering::Acquire), 1, "the child is its namespace's init");
    assert_ne!(reported, 1);
}
