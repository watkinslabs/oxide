use alloc::sync::{Arc, Weak};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static FINALIZED: AtomicU64 = AtomicU64::new(0);

fn record_final_drop(kind: NamespaceKind, id: NamespaceId) {
    assert_eq!(kind, NamespaceKind::Uts);
    FINALIZED.store(id.as_u64(), Ordering::Release);
}

#[test]
fn canonical_ownership_and_weak_registry_lifecycle() {
    let _serial = TEST_LOCK.lock().unwrap();
    let user = initial(NamespaceKind::User);
    for kind in [NamespaceKind::Cgroup, NamespaceKind::Ipc, NamespaceKind::Pid,
        NamespaceKind::Time, NamespaceKind::User, NamespaceKind::Uts]
    {
        let namespace = initial(kind);
        assert!(Arc::ptr_eq(&namespace, &initial(kind)));
        assert_eq!(namespace.id().as_u64(), 0);
        assert_eq!(namespace.nsfs_ino(), kind.initial_nsfs_ino());
        assert!(Arc::ptr_eq(&namespace.owner_user_namespace(), &user));
        assert!(namespace.parent().is_none());
    }

    let owner = allocate(NamespaceKind::User, Arc::clone(&user), Some(Arc::clone(&user))).unwrap();
    let parent = allocate(NamespaceKind::Pid, Arc::clone(&owner), None).unwrap();
    let owner_weak = Arc::downgrade(&owner);
    let parent_weak = Arc::downgrade(&parent);
    let child = allocate(NamespaceKind::Pid, owner, Some(parent)).unwrap();
    assert_eq!(Arc::strong_count(&child), 1, "registry indexes must both be weak");
    assert!(Arc::ptr_eq(&child.owner_user_namespace(), &owner_weak.upgrade().unwrap()));
    assert!(Arc::ptr_eq(&child.parent().unwrap(), &parent_weak.upgrade().unwrap()));
    assert!(owner_weak.upgrade().is_some(), "child must retain exact user owner");
    assert!(parent_weak.upgrade().is_some(), "child must retain exact parent");

    let child_id = child.id();
    let child_ino = child.nsfs_ino();
    assert!(Arc::ptr_eq(&lookup(NamespaceKind::Pid, child_id).unwrap(), &child));
    assert!(Arc::ptr_eq(&lookup_nsfs_ino(child_ino).unwrap(), &child));
    let retained = live_snapshot().into_iter()
        .find(|namespace| namespace.id() == child_id).unwrap();
    let final_drop = Arc::downgrade(&child);
    drop(child);
    assert!(final_drop.upgrade().is_some(), "snapshot must retain its owners");
    drop(retained);
    assert!(final_drop.upgrade().is_none(), "last retained reference must finalize owner");
    assert!(lookup(NamespaceKind::Pid, child_id).is_none());
    assert!(lookup_nsfs_ino(child_ino).is_none());

    let replacement = allocate(NamespaceKind::Pid, Arc::clone(&user), None).unwrap();
    assert_ne!(replacement.id(), child_id, "dead IDs must never be allocated again");
    assert!(lookup(NamespaceKind::Pid, child_id).is_none(), "dead ID must not resurrect");
}

#[test]
fn drop_cleans_exactly_both_weak_entries() {
    let _serial = TEST_LOCK.lock().unwrap();
    let user = initial(NamespaceKind::User);
    let baseline = crate::registry::index_lengths();
    let namespace = allocate(NamespaceKind::Uts, user, None).unwrap();
    assert_eq!(crate::registry::index_lengths(), (baseline.0 + 1, baseline.1 + 1));
    let weak: Weak<Namespace> = Arc::downgrade(&namespace);
    drop(namespace);
    assert!(weak.upgrade().is_none());
    assert_eq!(crate::registry::index_lengths(), baseline,
        "final drop must remove only its two identity-matched weak entries");
}

#[test]
fn allocation_rejects_inexact_relationships() {
    let _serial = TEST_LOCK.lock().unwrap();
    let user = initial(NamespaceKind::User);
    let pid = initial(NamespaceKind::Pid);
    assert!(matches!(allocate(NamespaceKind::Uts, Arc::clone(&pid), None),
        Err(AllocError::OwnerNotUserNamespace)));
    assert!(matches!(allocate(NamespaceKind::Uts, user, Some(pid)),
        Err(AllocError::ParentKindMismatch)));
}

#[test]
fn exact_owner_runs_registered_finalizer_once() {
    let _serial = TEST_LOCK.lock().unwrap();
    FINALIZED.store(0, Ordering::Release);
    let owner = allocate(NamespaceKind::Uts, initial(NamespaceKind::User), None).unwrap();
    let id = owner.id().as_u64();
    owner.register_finalizer(record_final_drop);
    owner.register_finalizer(record_final_drop);
    let pin = Arc::clone(&owner);
    drop(owner);
    assert_eq!(FINALIZED.load(Ordering::Acquire), 0);
    drop(pin);
    assert_eq!(FINALIZED.load(Ordering::Acquire), id);
}
