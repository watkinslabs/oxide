use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Barrier, OnceLock};

use super::*;
use crate::callback::CallbackSlot;

static NOTIFICATIONS: AtomicUsize = AtomicUsize::new(0);
const NO_DROP_TARGET: u64 = u64::MAX;
static DROP_TARGET: AtomicU64 = AtomicU64::new(NO_DROP_TARGET);
static DROP_ENTERED: OnceLock<Barrier> = OnceLock::new();
static DROP_RELEASE: OnceLock<Barrier> = OnceLock::new();

fn notify() { NOTIFICATIONS.fetch_add(1, Ordering::Relaxed); }
fn other_notify() { NOTIFICATIONS.fetch_add(2, Ordering::Relaxed); }
fn pause_target_drop(id: NetworkNamespaceId) {
    if id.as_u64() != DROP_TARGET.load(Ordering::Acquire) { return; }
    DROP_ENTERED.get().unwrap().wait();
    DROP_RELEASE.get().unwrap().wait();
}

#[test]
fn owner_registry_lifecycle_contract() {
    let initial_user = namespace_identity::initial(namespace_identity::NamespaceKind::User);
    let initial_uts = namespace_identity::initial(namespace_identity::NamespaceKind::Uts);
    assert!(matches!(allocate(initial_uts.pin()), Err(AllocError::OwnerNotUserNamespace)));
    assert!(matches!(allocate(initial_user.pin()),
        Err(AllocError::FinalDropCallbackMissing)));
    install_final_drop_callback(notify).unwrap();

    let init = initial();
    let init_again = initial();
    assert!(Arc::ptr_eq(&init, &init_again));
    assert_eq!(init.id().as_u64(), 0);
    assert_eq!(init.ns_id(), namespace_identity::NET_INIT_NS_ID);
    assert_eq!(init.identity().ns_id, namespace_identity::NET_INIT_NS_ID);
    assert!(namespace_identity::NamespacePin::ptr_eq(
        &init.owner_user_namespace(), &initial_user.pin()));
    assert_eq!(init.identity().nsfs_ino, 0x7200_0006);
    assert!(init.is_initial());
    drop(init_again);
    drop(init);
    assert!(lookup(NetworkNamespaceId(0)).is_some());

    let user_owner = namespace_identity::allocate(namespace_identity::NamespaceKind::User,
        initial_user.clone(), Some(initial_user.clone())).unwrap();
    let user_ns_id = user_owner.ns_id().as_u64();
    let owner_weak = namespace_identity::NamespaceRef::downgrade(&user_owner);
    let first = allocate(user_owner.pin()).unwrap();
    let second = allocate(initial_user.pin()).unwrap();
    let uts = namespace_identity::allocate(namespace_identity::NamespaceKind::Uts,
        user_owner.clone(), None).unwrap();
    let inodes = [first.identity().nsfs_ino, user_owner.nsfs_ino(), uts.nsfs_ino(),
        namespace_identity::MNT_INIT_NSFS_INO];
    for (index, inode) in inodes.iter().enumerate() {
        assert!(!inodes[..index].contains(inode),
            "network, User, UTS, and mount inodes are unique");
    }
    assert_ne!(first.identity().nsfs_ino,
        namespace_identity::initial(namespace_identity::NamespaceKind::User).nsfs_ino());
    assert!(first.identity().nsfs_ino > namespace_identity::MNT_INIT_NSFS_INO,
        "all dynamic nsfs inodes use the canonical allocator");
    assert!(uts.nsfs_ino() > namespace_identity::MNT_INIT_NSFS_INO);
    drop(uts);
    assert_eq!(Arc::strong_count(&first), 1, "registry must retain only Weak");
    assert!(first.id() < second.id());
    assert_eq!(first.peer_id(&second), None);
    assert_eq!(first.assign_peer_id(&second, 7), Ok(()));
    assert_eq!(first.peer_id(&second), Some(7));
    assert_eq!(first.assign_peer_id(&second, 8), Err(PeerIdError::Exists));
    assert_eq!(first.assign_peer_id(&initial(), 7), Err(PeerIdError::Exists));
    assert_eq!(first.assign_peer_id(&initial(), -1), Err(PeerIdError::Invalid));
    assert!(first.ns_id() > user_ns_id, "network IDs share the global allocator");
    assert!(second.ns_id() > first.ns_id(), "global namespace IDs are monotonic");
    assert_ne!(first.ns_id(), first.id().as_u64(),
        "network subsystem and Linux global IDs remain independent");
    assert_ne!(first.identity().nsfs_ino, second.identity().nsfs_ino);
    assert!(namespace_identity::NamespacePin::ptr_eq(
        &lookup(first.id()).unwrap().owner_user_namespace(), &user_owner.pin()));
    let canonical = namespace_identity::lookup_ns_id(namespace_identity::NsId::from_u64(
        first.ns_id())).expect("active network identity is canonical");
    assert!(namespace_identity::NamespacePin::ptr_eq(
        &canonical, &first.namespace_identity()));
    assert_eq!(canonical.kind(), namespace_identity::NamespaceKind::Net);
    drop(canonical);
    assert!(owner_weak.upgrade().is_some(), "network namespace must retain exact user owner");
    assert_eq!(lookup_u64(first.id().as_u64()).unwrap().id(), first.id());
    assert!(namespace_identity::live_snapshot().iter().any(|namespace|
        namespace.kind() == namespace_identity::NamespaceKind::Net
            && namespace.id().as_u64() == second.id().as_u64()));
    let list_pin = namespace_identity::lookup_ns_id(namespace_identity::NsId::from_u64(
        first.ns_id())).unwrap();
    drop(user_owner);

    let first_id = first.id();
    let first_clone = Arc::clone(&first);
    let before = NOTIFICATIONS.load(Ordering::Relaxed);
    drop(first);
    assert_eq!(NOTIFICATIONS.load(Ordering::Relaxed), before);
    drop(first_clone);
    assert_eq!(NOTIFICATIONS.load(Ordering::Relaxed), before + 1);
    assert!(lookup(first_id).is_none());
    assert!(namespace_identity::lookup_ns_id(list_pin.ns_id()).is_none(),
        "listns lifetime pin cannot retain concrete network activity");
    assert_eq!(list_pin.kind(), namespace_identity::NamespaceKind::Net);
    assert!(owner_weak.upgrade().is_none(), "network final drop releases exact user owner");
    assert_eq!(take_dead_namespace_ids().iter().filter(|id| **id == first_id).count(), 1);
    assert!(!take_dead_namespace_ids().contains(&first_id));
    assert!(finish_teardown(first_id));
    assert!(!finish_teardown(first_id));
    assert!(lookup(first_id).is_none(), "finished ID cannot be resurrected");

    let mut threads = alloc::vec::Vec::new();
    for _ in 0..16 {
        let owner = initial_user.clone();
        threads.push(std::thread::spawn(move || allocate(owner.pin()).unwrap()));
    }
    let mut namespaces: alloc::vec::Vec<_> = threads.into_iter()
        .map(|thread| thread.join().unwrap()).collect();
    namespaces.sort_by_key(|namespace| namespace.id());
    for pair in namespaces.windows(2) { assert!(pair[0].id() < pair[1].id()); }

    let lookup_first = allocate(initial_user.pin()).unwrap();
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

    let drop_first = allocate(initial_user.pin()).unwrap();
    let drop_first_id = drop_first.id();
    drop(drop_first);
    assert!(lookup(drop_first_id).is_none());

    let harvested = allocate(initial_user.pin()).unwrap();
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
    assert!(lookup(harvested_id).is_none(), "claimed ID cannot be resurrected");
    assert!(finish_teardown(harvested_id));
    assert!(!finish_teardown(harvested_id));
    assert!(lookup(harvested_id).is_none(), "finished ID cannot be resurrected");

    let in_progress = allocate(initial_user.pin()).unwrap();
    let in_progress_id = in_progress.id();
    let notifying = allocate(initial_user.pin()).unwrap();
    let notifying_id = notifying.id();
    DROP_TARGET.store(in_progress_id.as_u64(), Ordering::Release);
    DROP_ENTERED.set(Barrier::new(2)).unwrap();
    DROP_RELEASE.set(Barrier::new(2)).unwrap();
    crate::owner::set_drop_hook(Some(pause_target_drop));
    let in_progress_drop = std::thread::spawn(move || drop(in_progress));
    DROP_ENTERED.get().unwrap().wait();
    assert!(lookup(in_progress_id).is_none(),
        "weak owner reaches zero before its destructor publishes completion");
    drop(notifying);
    let notified_ids = take_dead_namespace_ids();
    assert!(notified_ids.contains(&notifying_id));
    assert!(!notified_ids.contains(&in_progress_id),
        "notification cannot stand in for another owner's final-drop completion");
    assert!(finish_teardown(notifying_id));
    DROP_RELEASE.get().unwrap().wait();
    in_progress_drop.join().unwrap();
    crate::owner::set_drop_hook(None);
    assert!(take_dead_namespace_ids().contains(&in_progress_id));
    assert!(finish_teardown(in_progress_id));
}

#[test]
fn shared_ns_id_errors_map_to_network_allocation_errors() {
    assert_eq!(crate::registry::ns_id_error(namespace_identity::AllocError::IdExhausted),
        AllocError::IdExhausted);
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
