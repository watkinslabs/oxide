use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

use namespace_identity::{allocate, initial, lookup, NamespaceId, NamespaceKind};

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
    let uts = allocate(NamespaceKind::Uts, Arc::clone(&user), None).unwrap();
    let uts_id = uts.id();
    assert!(source.replace_namespace(Arc::clone(&user)).is_ok());
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
