use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Barrier;

use super::*;
use crate::callback::CallbackSlot;

static NOTIFICATIONS: AtomicUsize = AtomicUsize::new(0);

fn notify() { NOTIFICATIONS.fetch_add(1, Ordering::Relaxed); }
fn other_notify() { NOTIFICATIONS.fetch_add(2, Ordering::Relaxed); }

#[test]
fn owner_registry_lifecycle_contract() {
    assert!(matches!(allocate(1), Err(AllocError::FinalDropCallbackMissing)));
    install_final_drop_callback(notify).unwrap();

    let init = initial();
    let init_again = initial();
    assert!(Arc::ptr_eq(&init, &init_again));
    assert_eq!(init.id().as_u64(), 0);
    assert_eq!(init.owner_user_ns(), 0);
    assert_eq!(init.identity().nsfs_ino, 0x7200_0006);
    assert!(init.is_initial());
    drop(init_again);
    drop(init);
    assert!(lookup(NetworkNamespaceId(0)).is_some());

    let first = allocate(41).unwrap();
    let second = allocate(42).unwrap();
    assert_eq!(Arc::strong_count(&first), 1, "registry must retain only Weak");
    assert!(first.id() < second.id());
    assert_ne!(first.identity().nsfs_ino, second.identity().nsfs_ino);
    assert_eq!(lookup(first.id()).unwrap().owner_user_ns(), 41);
    assert!(live_snapshot().iter().any(|namespace| namespace.id() == second.id()));

    let first_id = first.id();
    let first_clone = Arc::clone(&first);
    let before = NOTIFICATIONS.load(Ordering::Relaxed);
    drop(first);
    assert_eq!(NOTIFICATIONS.load(Ordering::Relaxed), before);
    drop(first_clone);
    assert_eq!(NOTIFICATIONS.load(Ordering::Relaxed), before + 1);
    assert!(lookup(first_id).is_none());
    assert_eq!(take_dead_namespace_ids().iter().filter(|id| **id == first_id).count(), 1);
    assert!(!take_dead_namespace_ids().contains(&first_id));

    let mut threads = alloc::vec::Vec::new();
    for owner in 0..16 {
        threads.push(std::thread::spawn(move || allocate(owner).unwrap()));
    }
    let mut namespaces: alloc::vec::Vec<_> = threads.into_iter()
        .map(|thread| thread.join().unwrap()).collect();
    namespaces.sort_by_key(|namespace| namespace.id());
    for pair in namespaces.windows(2) { assert!(pair[0].id() < pair[1].id()); }

    let raced = allocate(88).unwrap();
    let raced_id = raced.id();
    let barrier = Arc::new(Barrier::new(2));
    let peer_barrier = Arc::clone(&barrier);
    let lookup_thread = std::thread::spawn(move || {
        peer_barrier.wait();
        lookup(raced_id)
    });
    barrier.wait();
    drop(raced);
    if let Some(pinned) = lookup_thread.join().unwrap() {
        assert_eq!(pinned.id(), raced_id);
        drop(pinned);
    }
    assert!(lookup(raced_id).is_none());
    assert_eq!(take_dead_namespace_ids().iter().filter(|id| **id == raced_id).count(), 1);
}

#[test]
fn callback_slot_is_idempotent_but_immutable() {
    let slot = CallbackSlot::new();
    assert!(!slot.installed());
    assert_eq!(slot.install(notify), Ok(()));
    assert_eq!(slot.install(notify), Ok(()));
    assert_eq!(slot.install(other_notify), Err(InstallError::AlreadyInstalled));
}
