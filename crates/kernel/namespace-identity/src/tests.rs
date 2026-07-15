use alloc::sync::{Arc, Weak};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::sync_channel;

use super::*;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static FINALIZED: AtomicU64 = AtomicU64::new(0);
static FINALIZER_CALLS: AtomicU64 = AtomicU64::new(0);

fn record_final_drop(kind: NamespaceKind, id: NamespaceId) {
    assert_eq!(kind, NamespaceKind::Uts);
    FINALIZED.store(id.as_u64(), Ordering::Release);
    FINALIZER_CALLS.fetch_add(1, Ordering::AcqRel);
}

fn reset_finalizer_record() {
    FINALIZED.store(0, Ordering::Release);
    FINALIZER_CALLS.store(0, Ordering::Release);
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
        assert_eq!(namespace.ns_id(), kind.initial_ns_id());
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
    let child_ns_id = child.ns_id();
    let child_ino = child.nsfs_ino();
    assert!(Arc::ptr_eq(&lookup(NamespaceKind::Pid, child_id).unwrap(), &child));
    assert!(Arc::ptr_eq(&lookup_ns_id(child_ns_id).unwrap(), &child));
    assert!(Arc::ptr_eq(&lookup_nsfs_ino(child_ino).unwrap(), &child));
    let retained = live_snapshot().into_iter()
        .find(|namespace| namespace.id() == child_id).unwrap();
    let final_drop = Arc::downgrade(&child);
    drop(child);
    assert!(final_drop.upgrade().is_some(), "snapshot must retain its owners");
    drop(retained);
    assert!(final_drop.upgrade().is_none(), "last retained reference must finalize owner");
    assert!(lookup(NamespaceKind::Pid, child_id).is_none());
    assert!(lookup_ns_id(child_ns_id).is_none());
    assert!(lookup_nsfs_ino(child_ino).is_none());

    let replacement = allocate(NamespaceKind::Pid, Arc::clone(&user), None).unwrap();
    assert_ne!(replacement.id(), child_id, "dead IDs must never be allocated again");
    assert!(replacement.ns_id() > child_ns_id, "global namespace IDs must be monotonic");
    assert!(lookup(NamespaceKind::Pid, child_id).is_none(), "dead ID must not resurrect");
}

#[test]
fn linux_dynamic_namespace_id_space_starts_after_reserved_gap() {
    assert_eq!(crate::uapi::FIRST_DYNAMIC_NS_ID, 10);
    assert_eq!(crate::uapi::MNT_INIT_NS_ID, 8);
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
    reset_finalizer_record();
    let owner = allocate(NamespaceKind::Uts, initial(NamespaceKind::User), None).unwrap();
    let id = owner.id().as_u64();
    owner.register_finalizer(record_final_drop);
    owner.register_finalizer(record_final_drop);
    let pin = Arc::clone(&owner);
    drop(owner);
    assert_eq!(FINALIZED.load(Ordering::Acquire), 0);
    drop(pin);
    assert_eq!(FINALIZED.load(Ordering::Acquire), id);
    assert_eq!(FINALIZER_CALLS.load(Ordering::Acquire), 1);
}

#[test]
fn lookup_first_pins_exact_owner_across_final_external_drop() {
    let _serial = TEST_LOCK.lock().unwrap();
    reset_finalizer_record();
    let baseline = crate::registry::index_lengths();
    let owner = allocate(NamespaceKind::Uts, initial(NamespaceKind::User), None).unwrap();
    let id = owner.id();
    let nsfs_ino = owner.nsfs_ino();
    let pointer = Arc::as_ptr(&owner) as usize;
    let weak = Arc::downgrade(&owner);
    owner.register_finalizer(record_final_drop);
    assert_eq!(crate::registry::index_lengths(), (baseline.0 + 1, baseline.1 + 1));

    let (lookup_go_tx, lookup_go_rx) = sync_channel(0);
    let (lookup_pinned_tx, lookup_pinned_rx) = sync_channel(0);
    let (release_pin_tx, release_pin_rx) = sync_channel(0);
    let (drop_go_tx, drop_go_rx) = sync_channel(0);
    let (external_dropped_tx, external_dropped_rx) = sync_channel(0);
    std::thread::scope(|scope| {
        scope.spawn(move || {
            lookup_go_rx.recv().unwrap();
            let pin = lookup(NamespaceKind::Uts, id).expect("live weak index must upgrade");
            assert_eq!(Arc::as_ptr(&pin) as usize, pointer);
            lookup_pinned_tx.send(()).unwrap();
            release_pin_rx.recv().unwrap();
            drop(pin);
        });
        scope.spawn(move || {
            drop_go_rx.recv().unwrap();
            drop(owner);
            external_dropped_tx.send(()).unwrap();
        });

        lookup_go_tx.send(()).unwrap();
        lookup_pinned_rx.recv().unwrap();
        drop_go_tx.send(()).unwrap();
        external_dropped_rx.recv().unwrap();
        assert!(weak.upgrade().is_some(), "lookup pin must retain exact owner");
        assert_eq!(FINALIZER_CALLS.load(Ordering::Acquire), 0);
        assert_eq!(crate::registry::index_lengths(), (baseline.0 + 1, baseline.1 + 1));
        release_pin_tx.send(()).unwrap();
    });

    assert!(weak.upgrade().is_none());
    assert_eq!(FINALIZED.load(Ordering::Acquire), id.as_u64());
    assert_eq!(FINALIZER_CALLS.load(Ordering::Acquire), 1);
    assert_eq!(crate::registry::index_lengths(), baseline);
    assert!(lookup(NamespaceKind::Uts, id).is_none());
    assert!(lookup_nsfs_ino(nsfs_ino).is_none());
}

#[test]
fn final_drop_first_prevents_lookup_and_id_resurrection() {
    let _serial = TEST_LOCK.lock().unwrap();
    reset_finalizer_record();
    let baseline = crate::registry::index_lengths();
    let owner = allocate(NamespaceKind::Uts, initial(NamespaceKind::User), None).unwrap();
    let id = owner.id();
    let nsfs_ino = owner.nsfs_ino();
    let weak = Arc::downgrade(&owner);
    owner.register_finalizer(record_final_drop);
    assert_eq!(crate::registry::index_lengths(), (baseline.0 + 1, baseline.1 + 1));

    let (drop_go_tx, drop_go_rx) = sync_channel(0);
    let (final_drop_done_tx, final_drop_done_rx) = sync_channel(0);
    let (lookup_go_tx, lookup_go_rx) = sync_channel(0);
    let (lookup_result_tx, lookup_result_rx) = sync_channel(0);
    std::thread::scope(|scope| {
        scope.spawn(move || {
            drop_go_rx.recv().unwrap();
            drop(owner);
            final_drop_done_tx.send(()).unwrap();
        });
        scope.spawn(move || {
            lookup_go_rx.recv().unwrap();
            lookup_result_tx.send(lookup(NamespaceKind::Uts, id).is_some()).unwrap();
        });

        drop_go_tx.send(()).unwrap();
        final_drop_done_rx.recv().unwrap();
        assert!(weak.upgrade().is_none());
        assert_eq!(FINALIZED.load(Ordering::Acquire), id.as_u64());
        assert_eq!(FINALIZER_CALLS.load(Ordering::Acquire), 1);
        assert_eq!(crate::registry::index_lengths(), baseline);
        lookup_go_tx.send(()).unwrap();
        assert!(!lookup_result_rx.recv().unwrap(), "dead weak index must not upgrade");
    });

    assert!(lookup_nsfs_ino(nsfs_ino).is_none());
    let replacement = allocate(NamespaceKind::Uts, initial(NamespaceKind::User), None).unwrap();
    assert_ne!(replacement.id(), id, "finalized ID must never be reused");
    assert!(lookup(NamespaceKind::Uts, id).is_none(), "finalized ID must not resurrect");
    assert_eq!(FINALIZER_CALLS.load(Ordering::Acquire), 1);
}
