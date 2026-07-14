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

    let lookup_first = allocate(88).unwrap();
    let lookup_first_id = lookup_first.id();
    let pinned_barrier = Arc::new(Barrier::new(2));
    let release_barrier = Arc::new(Barrier::new(2));
    let peer_pinned = Arc::clone(&pinned_barrier);
    let peer_release = Arc::clone(&release_barrier);
    let lookup_thread = std::thread::spawn(move || {
        let pinned = lookup(lookup_first_id).unwrap();
        peer_pinned.wait();
        peer_release.wait();
        pinned
    });
    pinned_barrier.wait();
    drop(lookup_first);
    assert_eq!(lookup(lookup_first_id).unwrap().id(), lookup_first_id);
    release_barrier.wait();
    let pinned = lookup_thread.join().unwrap();
    drop(pinned);
    assert!(lookup(lookup_first_id).is_none());

    let drop_first = allocate(89).unwrap();
    let drop_first_id = drop_first.id();
    drop(drop_first);
    assert!(lookup(drop_first_id).is_none());

    let harvested = allocate(90).unwrap();
    let harvested_id = harvested.id();
    drop(harvested);
    let barrier = Arc::new(Barrier::new(8));
    let mut harvesters = alloc::vec::Vec::new();
    for _ in 0..8 {
        let peer_barrier = Arc::clone(&barrier);
        harvesters.push(std::thread::spawn(move || {
            peer_barrier.wait();
            take_dead_namespace_ids()
        }));
    }
    let claimed = harvesters.into_iter().flat_map(|thread| thread.join().unwrap())
        .filter(|id| *id == harvested_id).count();
    assert_eq!(claimed, 1);
    assert!(!take_dead_namespace_ids().contains(&harvested_id));
}

#[test]
fn callback_slot_is_idempotent_but_immutable() {
    let slot = CallbackSlot::new();
    assert!(!slot.installed());
    assert_eq!(slot.install(notify), Ok(()));
    assert_eq!(slot.install(notify), Ok(()));
    assert_eq!(slot.install(other_notify), Err(InstallError::AlreadyInstalled));
}

#[test]
fn callback_install_publication_is_atomic() {
    let slot = Arc::new(CallbackSlot::new());
    let barrier = Arc::new(Barrier::new(2));
    let install_slot = Arc::clone(&slot);
    let install_barrier = Arc::clone(&barrier);
    let installer = std::thread::spawn(move || {
        install_barrier.wait();
        install_slot.install(notify).unwrap();
    });
    barrier.wait();
    while !slot.installed() { core::hint::spin_loop(); }
    installer.join().unwrap();
}
