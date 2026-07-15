use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, Ordering};
use std::sync::Barrier;

use namespace_identity::{allocate, initial, lookup, NamespaceId, NamespaceKind, NamespaceRef};

use crate::{SchedClass, Task, TaskState};

static EXIT_TASK: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static FINALIZER_STATE: AtomicU8 = AtomicU8::new(u8::MAX);

fn observe_final_drop(kind: NamespaceKind, _id: NamespaceId) {
    assert_eq!(kind, NamespaceKind::Ipc);
    let task = EXIT_TASK.load(Ordering::Acquire);
    if task.is_null() { return; }
    // SAFETY: test retains Arc<Task> until callback completes and clears the pointer before drop.
    FINALIZER_STATE.store(unsafe { (*task).state() } as u8, Ordering::Release);
}

fn task(tid: u32) -> Task {
    Task::new(tid, "namespace-owner", SchedClass::Normal { weight: 1024 })
}

#[test]
fn namespace_snapshot_is_one_retained_set() {
    let source = task(301);
    let destination = task(302);
    let user = allocate(NamespaceKind::User, initial(NamespaceKind::User),
        Some(initial(NamespaceKind::User))).unwrap();
    let uts = allocate(NamespaceKind::Uts, user.clone(), None).unwrap();
    let uts_id = uts.id();
    assert!(source.replace_namespace(user.clone()).is_ok());
    assert!(source.replace_namespace(uts).is_ok());

    assert!(destination.replace_namespace_set(source.namespace_snapshot().unwrap()).is_ok());
    source.release_namespaces();
    assert!(source.namespace_snapshot().is_none());
    assert_eq!(destination.namespace_id(NamespaceKind::Uts), Some(uts_id.as_u64()));
    assert!(lookup(NamespaceKind::Uts, uts_id).is_some(), "destination pins exact owner");
}

#[test]
fn mark_done_releases_all_nonnetwork_membership_before_zombie() {
    FINALIZER_STATE.store(u8::MAX, Ordering::Release);
    let task = Arc::new(task(303));
    let user = task.namespace_owner(NamespaceKind::User).unwrap();
    let ipc = allocate(NamespaceKind::Ipc, user, None).unwrap();
    let id = ipc.id();
    ipc.register_finalizer(observe_final_drop);
    assert!(task.replace_namespace(ipc).is_ok());
    EXIT_TASK.store(Arc::as_ptr(&task) as *mut Task, Ordering::Release);

    task.mark_done();
    assert_eq!(FINALIZER_STATE.load(Ordering::Acquire), TaskState::Runnable as u8,
        "exact namespace finalizer must run before Zombie publication");
    assert_eq!(task.state(), TaskState::Zombie);
    assert!(task.namespace_snapshot().is_none());
    assert!(task.mount_namespace_snapshot().is_none());
    assert!(lookup(NamespaceKind::Ipc, id).is_none(),
        "pidfd-style retained Task cannot retain namespace membership");
    EXIT_TASK.store(ptr::null_mut(), Ordering::Release);
}

#[test]
fn released_namespace_set_is_terminal() {
    let task = task(304);
    task.release_namespaces();
    let user = initial(NamespaceKind::User);
    let uts = allocate(NamespaceKind::Uts, user, None).unwrap();
    assert!(task.replace_namespace(uts).is_err());
    assert!(task.namespace_snapshot().is_none());
}

#[test]
fn time_for_children_owner_is_independent_and_snapshotted() {
    let source = task(305);
    let destination = task(306);
    let initial_time = source.namespace_owner(NamespaceKind::Time).unwrap();
    let current = allocate(NamespaceKind::Time, initial(NamespaceKind::User), None).unwrap();
    let children = allocate(NamespaceKind::Time, initial(NamespaceKind::User), None).unwrap();
    let current_id = current.id();
    let children_id = children.id();

    assert!(source.replace_time_namespace_for_children(children.clone()).is_ok());
    assert!(NamespaceRef::ptr_eq(&source.namespace_owner(NamespaceKind::Time).unwrap(), &initial_time),
        "for-children replacement must not change current TIME owner");
    assert!(source.replace_namespace(current.clone()).is_ok());
    assert!(NamespaceRef::ptr_eq(&source.time_namespace_for_children().unwrap(), &children));

    let snapshot = source.namespace_snapshot().unwrap();
    assert!(NamespaceRef::ptr_eq(&snapshot.time, &current));
    assert!(NamespaceRef::ptr_eq(&snapshot.time_for_children, &children));
    drop(current);
    drop(children);
    source.release_namespaces();
    assert!(lookup(NamespaceKind::Time, current_id).is_some());
    assert!(lookup(NamespaceKind::Time, children_id).is_some());

    assert!(destination.replace_namespace_set(snapshot).is_ok());
    assert_eq!(destination.namespace_owner(NamespaceKind::Time).unwrap().id(), current_id);
    assert_eq!(destination.time_namespace_for_children().unwrap().id(), children_id);
}

#[test]
fn time_namespace_pair_replacement_is_atomic_for_snapshots() {
    const ITERATIONS: usize = 20_000;
    let task = Arc::new(task(307));
    let a_current = allocate(NamespaceKind::Time, initial(NamespaceKind::User), None).unwrap();
    let a_children = allocate(NamespaceKind::Time, initial(NamespaceKind::User), None).unwrap();
    let b_current = allocate(NamespaceKind::Time, initial(NamespaceKind::User), None).unwrap();
    let b_children = allocate(NamespaceKind::Time, initial(NamespaceKind::User), None).unwrap();
    let a_ids = (a_current.id(), a_children.id());
    let b_ids = (b_current.id(), b_children.id());
    assert!(task.replace_time_namespace_pair(
        a_current.clone(), a_children.clone()).is_ok());
    assert!(NamespaceRef::ptr_eq(&task.namespace_owner(NamespaceKind::Time).unwrap(), &a_current));
    assert!(NamespaceRef::ptr_eq(&task.time_namespace_for_children().unwrap(), &a_children));

    let start = Arc::new(Barrier::new(3));
    let finished = Arc::new(AtomicBool::new(false));
    let replacing_task = Arc::clone(&task);
    let replacing_start = Arc::clone(&start);
    let replacing_finished = Arc::clone(&finished);
    let replacer = std::thread::spawn(move || {
        replacing_start.wait();
        for iteration in 0..ITERATIONS {
            let pair = if iteration % 2 == 0 {
                (b_current.clone(), b_children.clone())
            } else {
                (a_current.clone(), a_children.clone())
            };
            assert!(replacing_task.replace_time_namespace_pair(pair.0, pair.1).is_ok());
        }
        replacing_finished.store(true, Ordering::Release);
    });
    let snapshot_task = Arc::clone(&task);
    let snapshot_start = Arc::clone(&start);
    let snapshotter = std::thread::spawn(move || {
        snapshot_start.wait();
        for _ in 0..ITERATIONS {
            let snapshot = snapshot_task.namespace_snapshot().unwrap();
            let ids = (snapshot.time.id(), snapshot.time_for_children.id());
            assert!(ids == a_ids || ids == b_ids, "snapshot observed a torn TIME pair");
        }
        while !finished.load(Ordering::Acquire) { std::thread::yield_now(); }
    });
    start.wait();
    replacer.join().unwrap();
    snapshotter.join().unwrap();
}

#[test]
fn time_namespace_replacements_return_rejected_owners() {
    let task = task(308);
    let current = allocate(NamespaceKind::Time, initial(NamespaceKind::User), None).unwrap();
    let wrong = allocate(NamespaceKind::Uts, initial(NamespaceKind::User), None).unwrap();
    let current_id = current.id();
    let wrong_id = wrong.id();
    let (returned_current, returned_wrong) = task.replace_time_namespace_pair(current, wrong)
        .expect_err("mixed-kind pair must be rejected");
    assert_eq!(returned_current.id(), current_id);
    assert_eq!(returned_wrong.id(), wrong_id);

    let wrong = allocate(NamespaceKind::Ipc, initial(NamespaceKind::User), None).unwrap();
    let wrong_id = wrong.id();
    let returned = task.replace_time_namespace_for_children(wrong)
        .expect_err("non-TIME child owner must be rejected");
    assert_eq!(returned.id(), wrong_id);
}

#[test]
fn release_namespaces_drops_both_time_owners() {
    let task = task(309);
    let current = allocate(NamespaceKind::Time, initial(NamespaceKind::User), None).unwrap();
    let children = allocate(NamespaceKind::Time, initial(NamespaceKind::User), None).unwrap();
    let current_id = current.id();
    let children_id = children.id();
    assert!(task.replace_time_namespace_pair(current, children).is_ok());

    task.release_namespaces();
    assert!(task.namespace_owner(NamespaceKind::Time).is_none());
    assert!(task.time_namespace_for_children().is_none());
    assert!(lookup(NamespaceKind::Time, current_id).is_none());
    assert!(lookup(NamespaceKind::Time, children_id).is_none());
}
