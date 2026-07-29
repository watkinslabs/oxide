use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Barrier, Mutex};

use super::*;

static SERIAL: Mutex<()> = Mutex::new(());
static FINALIZED: AtomicUsize = AtomicUsize::new(0);

fn finalized(_kind: NamespaceKind, _id: NamespaceId) {
    FINALIZED.fetch_add(1, Ordering::Relaxed);
}

fn ids(owners: &[NamespacePin]) -> alloc::vec::Vec<u64> {
    owners.iter().map(|owner| owner.ns_id().as_u64()).collect()
}

#[test]
fn all_eight_initial_kinds_are_canonical() {
    let _serial = SERIAL.lock().unwrap();
    for kind in NamespaceKind::ALL {
        let first = initial(kind);
        let second = initial(kind);
        assert!(NamespaceRef::ptr_eq(&first, &second));
        assert_eq!(first.kind(), kind);
        assert_eq!(first.id().as_u64(), 0);
        assert_eq!(first.ns_id(), kind.initial_ns_id());
        assert_eq!(first.nsfs_ino(), kind.initial_nsfs_ino());
    }
}

#[test]
fn pid_memfd_scope_is_inherited_and_retained_when_parent_lowers() {
    let _serial = SERIAL.lock().unwrap();
    let user = initial(NamespaceKind::User);
    let parent = allocate(NamespaceKind::Pid, user.clone(), None).unwrap();
    parent.set_pid_memfd_noexec_scope(PID_MEMFD_NOEXEC_SCOPE_NOEXEC_SEAL).unwrap();
    let child = allocate(NamespaceKind::Pid, user, Some(parent.clone())).unwrap();

    assert_eq!(child.pid_memfd_noexec_scope(), Ok(PID_MEMFD_NOEXEC_SCOPE_NOEXEC_SEAL));
    parent.set_pid_memfd_noexec_scope(PID_MEMFD_NOEXEC_SCOPE_EXEC).unwrap();
    assert_eq!(child.pid_memfd_noexec_scope(), Ok(PID_MEMFD_NOEXEC_SCOPE_NOEXEC_SEAL),
        "a child retains the scope copied at PID namespace creation");
}

#[test]
fn pid_memfd_scope_cannot_drop_below_effective_parent() {
    let _serial = SERIAL.lock().unwrap();
    let user = initial(NamespaceKind::User);
    let parent = allocate(NamespaceKind::Pid, user.clone(), None).unwrap();
    let child = allocate(NamespaceKind::Pid, user, Some(parent.clone())).unwrap();
    parent.set_pid_memfd_noexec_scope(PID_MEMFD_NOEXEC_SCOPE_NOEXEC_ENFORCED).unwrap();

    assert_eq!(child.pid_memfd_noexec_scope(), Ok(PID_MEMFD_NOEXEC_SCOPE_NOEXEC_ENFORCED));
    assert_eq!(child.set_pid_memfd_noexec_scope(PID_MEMFD_NOEXEC_SCOPE_NOEXEC_SEAL),
        Err(PidMemfdNoexecError::BelowParent));
    assert_eq!(child.set_pid_memfd_noexec_scope(3), Err(PidMemfdNoexecError::OutOfRange));
    assert_eq!(initial(NamespaceKind::Uts).pid_memfd_noexec_scope(),
        Err(PidMemfdNoexecError::NotPidNamespace));
}

#[test]
fn passive_owner_retains_lifetime_without_activity() {
    let _serial = SERIAL.lock().unwrap();
    let init_user = initial(NamespaceKind::User);
    let user = allocate(NamespaceKind::User, init_user.clone(), Some(init_user)).unwrap();
    let user_id = user.ns_id();
    let weak = NamespaceRef::downgrade(&user);
    let child = allocate_inactive(NamespaceKind::Uts, user.clone(), None).unwrap();
    drop(user);

    assert!(weak.is_alive(), "child retains exact owner identity lifetime");
    assert!(lookup_ns_id(user_id).is_none(), "passive owner is not listns-active");
    assert!(!live_snapshot().iter().any(|owner| owner.ns_id() == user_id));

    drop(child);
    assert!(!weak.is_alive(), "last passive edge releases owner lifetime");
}

#[test]
fn weak_upgrade_rejects_inactive_lifetime() {
    let _serial = SERIAL.lock().unwrap();
    let pin = allocate_inactive(NamespaceKind::Uts,
        initial(NamespaceKind::User), None).unwrap();
    let weak = NamespacePin::downgrade(&pin);
    assert!(weak.is_alive());
    assert!(weak.upgrade().is_none(), "weak lifetime lookup cannot perform first activation");

    let active = pin.activate();
    assert!(weak.upgrade().is_some());
    drop(active);
    assert!(weak.upgrade().is_none(), "lifetime pins cannot retain active membership");
    assert!(weak.is_alive());
    drop(pin);
    assert!(!weak.is_alive());
}

#[test]
fn metadata_traversal_does_not_publish_passive_namespaces() {
    let _serial = SERIAL.lock().unwrap();
    let init_user = initial(NamespaceKind::User);
    let parent = allocate(NamespaceKind::Pid, init_user.clone(), None).unwrap();
    let parent_id = parent.ns_id();
    let child = allocate_inactive(NamespaceKind::Pid, init_user, Some(parent.clone())).unwrap();
    drop(parent);
    assert!(lookup_ns_id(parent_id).is_none());

    let retained_parent = child.parent().unwrap();
    let retained_owner = child.owner_user_namespace();
    assert_eq!(retained_owner.kind(), NamespaceKind::User);
    assert!(lookup_ns_id(parent_id).is_none(), "parent metadata must not publish activity");
    drop(retained_parent);
    assert!(lookup_ns_id(parent_id).is_none());
}

#[test]
fn active_membership_cascades_owner_chain_once_per_namespace() {
    let _serial = SERIAL.lock().unwrap();
    let init_user = initial(NamespaceKind::User);
    let outer = allocate(NamespaceKind::User, init_user.clone(), Some(init_user)).unwrap();
    let outer_id = outer.ns_id();
    let inner = allocate(NamespaceKind::User, outer.clone(), Some(outer.clone())).unwrap();
    let inner_id = inner.ns_id();
    let first = allocate(NamespaceKind::Uts, inner.clone(), None).unwrap();
    let second = allocate(NamespaceKind::Ipc, inner.clone(), None).unwrap();
    drop(inner); drop(outer);

    assert!(lookup_ns_id(inner_id).is_some());
    assert!(lookup_ns_id(outer_id).is_some());
    drop(first);
    assert!(lookup_ns_id(inner_id).is_some(), "second child retains one owner cascade");
    assert!(lookup_ns_id(outer_id).is_some());
    drop(second);
    assert!(lookup_ns_id(inner_id).is_none());
    assert!(lookup_ns_id(outer_id).is_none());
}

#[test]
fn child_activity_cascades_to_owner_not_hierarchical_parent() {
    let _serial = SERIAL.lock().unwrap();
    let init_user = initial(NamespaceKind::User);
    let owner = allocate(NamespaceKind::User, init_user.clone(), Some(init_user.clone())).unwrap();
    let owner_id = owner.ns_id();
    let parent = allocate(NamespaceKind::Pid, init_user, None).unwrap();
    let parent_id = parent.ns_id();
    let child = allocate_inactive(NamespaceKind::Pid, owner.clone(), Some(parent.clone())).unwrap();
    drop(parent); drop(owner);
    assert!(lookup_ns_id(parent_id).is_none());
    assert!(lookup_ns_id(owner_id).is_none());

    let active = child.activate();
    assert!(lookup_ns_id(parent_id).is_none(), "parent is metadata, not active ownership");
    assert!(lookup_ns_id(owner_id).is_some(), "owning user namespace receives activity");
    drop(active);
    assert!(lookup_ns_id(owner_id).is_none());
}

#[test]
fn active_lookup_pin_does_not_extend_membership() {
    let _serial = SERIAL.lock().unwrap();
    let owner = allocate(NamespaceKind::Uts, initial(NamespaceKind::User), None).unwrap();
    let id = owner.ns_id();
    let pinned = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let peer_pinned = Arc::clone(&pinned);
    let peer_release = Arc::clone(&release);
    let thread = std::thread::spawn(move || {
        let acquired = lookup_ns_id(id).expect("active lookup wins race");
        peer_pinned.wait(); peer_release.wait(); acquired
    });

    pinned.wait();
    drop(owner);
    assert!(lookup_ns_id(id).is_none(), "list lookup pin does not retain activity");
    release.wait();
    let acquired = thread.join().unwrap();
    assert_eq!(acquired.ns_id(), id, "raced pin retains exact identity lifetime");
    drop(acquired);
    assert!(lookup_ns_id(id).is_none());
}

#[test]
fn global_kind_and_direct_owner_indexes_are_cursor_ordered() {
    let _serial = SERIAL.lock().unwrap();
    let init_user = initial(NamespaceKind::User);
    let user = allocate(NamespaceKind::User, init_user.clone(), Some(init_user)).unwrap();
    let first = allocate(NamespaceKind::Uts, user.clone(), None).unwrap();
    let second = allocate(NamespaceKind::Ipc, user.clone(), None).unwrap();
    let third = allocate(NamespaceKind::Uts, user.clone(), None).unwrap();

    let global = active_page(user.ns_id(), usize::MAX);
    let global_ids = ids(&global);
    assert!(global_ids.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(global_ids.contains(&first.ns_id().as_u64()));
    assert!(global_ids.contains(&second.ns_id().as_u64()));

    let kind = active_kind_page(NamespaceKind::Uts, first.ns_id(), usize::MAX);
    assert_eq!(ids(&kind), [third.ns_id().as_u64()]);

    let owned = active_owner_page(&user.pin(), first.ns_id(), usize::MAX);
    assert_eq!(ids(&owned), [second.ns_id().as_u64(), third.ns_id().as_u64()]);
}

#[test]
fn all_initial_namespaces_remain_permanently_active() {
    let _serial = SERIAL.lock().unwrap();
    let owners: alloc::vec::Vec<_> = NamespaceKind::ALL.into_iter().map(|kind| {
        let owner = initial(kind);
        let weak = NamespaceRef::downgrade(&owner);
        let id = owner.ns_id();
        drop(owner);
        (kind, id, weak)
    }).collect();
    for (kind, id, weak) in owners {
        assert_eq!(lookup_ns_id(id).unwrap().kind(), kind);
        assert_eq!(weak.upgrade().unwrap().kind(), kind);
    }
}

#[test]
fn finalizer_runs_at_lifetime_end_not_activity_end() {
    let _serial = SERIAL.lock().unwrap();
    let before = FINALIZED.load(Ordering::Relaxed);
    let user = allocate(NamespaceKind::User, initial(NamespaceKind::User), None).unwrap();
    user.register_finalizer(finalized);
    let child = allocate(NamespaceKind::Uts, user.clone(), None).unwrap();
    drop(user);
    assert_eq!(FINALIZED.load(Ordering::Relaxed), before);
    drop(child);
    assert_eq!(FINALIZED.load(Ordering::Relaxed), before + 1);
}
