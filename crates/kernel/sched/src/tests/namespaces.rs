use alloc::sync::Arc;

use namespace_identity::{allocate, initial, lookup, NamespaceKind};

use crate::{SchedClass, Task, TaskState};

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
    let task = task(303);
    let user = task.namespace_owner(NamespaceKind::User).unwrap();
    let ipc = allocate(NamespaceKind::Ipc, user, None).unwrap();
    let id = ipc.id();
    assert!(task.replace_namespace(ipc).is_ok());

    task.mark_done();
    assert_eq!(task.state(), TaskState::Zombie);
    assert!(task.namespace_snapshot().is_none());
    assert!(task.mount_namespace_snapshot().is_none());
    assert!(lookup(NamespaceKind::Ipc, id).is_none(),
        "pidfd-style retained Task cannot retain namespace membership");
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
