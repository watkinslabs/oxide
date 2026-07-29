use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};
use std::sync::{Arc, Barrier, Mutex, MutexGuard};

use network_namespace::{allocate, finish_teardown, initial, install_final_drop_callback, lookup,
    take_dead_namespace_ids, NetworkNamespaceId};

use crate::{SchedClass, Task, TaskState};

static EXIT_TASK: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static DROP_STATE: AtomicU8 = AtomicU8::new(u8::MAX);
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn test_lock() -> MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn install_callback() { install_final_drop_callback(observe_final_drop).unwrap(); }

fn finish_claimed(ids: &[NetworkNamespaceId]) {
    for id in ids { assert!(finish_teardown(*id)); }
}

fn observe_final_drop() {
    let task = EXIT_TASK.load(Ordering::Acquire);
    if task.is_null() { return; }
    // SAFETY: the test keeps its Arc<Task> alive until after the callback and
    // clears EXIT_TASK before dropping that final strong task reference.
    let state = unsafe { (*task).state.load(Ordering::Acquire) };
    DROP_STATE.store(state, Ordering::Release);
}

fn task() -> Arc<Task> {
    Arc::new(Task::new(41, "netns-owner", SchedClass::Normal { weight: 1024 }))
}

fn namespace() -> network_namespace::NetworkNamespaceRef {
    allocate(namespace_identity::initial(namespace_identity::NamespaceKind::User)).unwrap()
}

#[test]
fn task_namespace_slot_snapshots_replaces_and_releases_owners() {
    let _guard = test_lock();
    install_callback();
    let task = task();
    let init = initial();
    let snapshot = task.network_namespace_snapshot().expect("initial owner");
    assert!(Arc::ptr_eq(&snapshot, &init));
    assert_eq!(task.network_namespace_id(), Some(init.id()));

    assert!(task.replace_network_namespace(Arc::clone(&init)).is_ok());
    let replaced = task.network_namespace_snapshot().expect("replaced owner");
    assert!(Arc::ptr_eq(&replaced, &init));

    task.release_network_namespace();
    assert!(task.network_namespace_snapshot().is_none());
    assert_eq!(task.network_namespace_id(), None);
    assert!(task.replace_network_namespace(Arc::clone(&init)).is_err());
    assert!(task.network_namespace_snapshot().is_none());
}

#[test]
fn mark_done_releases_final_namespace_owner_before_zombie_publication() {
    let _guard = test_lock();
    install_callback();
    DROP_STATE.store(u8::MAX, Ordering::Release);

    let task = task();
    let namespace = namespace();
    let id = namespace.id();
    assert!(task.replace_network_namespace(namespace).is_ok());
    EXIT_TASK.store(Arc::as_ptr(&task) as *mut Task, Ordering::Release);

    task.mark_done();

    assert_eq!(DROP_STATE.load(Ordering::Acquire), TaskState::Runnable as u8);
    assert_eq!(task.state(), TaskState::Zombie);
    assert!(task.network_namespace_snapshot().is_none());
    assert!(lookup(id).is_none(), "pidfd-style task pin must not retain namespace");
    EXIT_TASK.store(ptr::null_mut(), Ordering::Release);
    let dead = take_dead_namespace_ids();
    assert_eq!(dead.iter().filter(|dead_id| **dead_id == id).count(), 1);
    finish_claimed(&dead);
}

#[test]
fn snapshot_pin_survives_concurrent_swap_and_release() {
    let _guard = test_lock();
    install_callback();
    let task = task();
    let old = namespace();
    let old_id = old.id();
    assert!(task.replace_network_namespace(old).is_ok());

    let pinned = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let peer_task = Arc::clone(&task);
    let peer_pinned = Arc::clone(&pinned);
    let peer_release = Arc::clone(&release);
    let snapshotter = std::thread::spawn(move || {
        let snapshot = peer_task.network_namespace_snapshot().expect("old owner snapshot");
        assert_eq!(snapshot.id(), old_id);
        peer_pinned.wait();
        peer_release.wait();
        drop(snapshot);
    });

    pinned.wait();
    let replacement = namespace();
    let replacement_id = replacement.id();
    assert!(task.replace_network_namespace(replacement).is_ok());
    task.release_network_namespace();
    assert!(task.network_namespace_snapshot().is_none());
    assert!(lookup(old_id).is_some(), "snapshot must pin the replaced owner");
    assert!(lookup(replacement_id).is_none(), "release must drop the replacement owner");

    let first_dead = take_dead_namespace_ids();
    assert!(!first_dead.contains(&old_id), "live snapshot cannot be teardown-claimed");
    assert_eq!(first_dead.iter().filter(|id| **id == replacement_id).count(), 1);
    finish_claimed(&first_dead);
    release.wait();
    snapshotter.join().unwrap();

    assert!(lookup(old_id).is_none());
    let second_dead = take_dead_namespace_ids();
    assert_eq!(second_dead.iter().filter(|id| **id == old_id).count(), 1);
    finish_claimed(&second_dead);
}

#[test]
fn competing_swap_and_release_cannot_restore_task_membership() {
    const ROUNDS: u64 = 32;
    let _guard = test_lock();
    install_callback();
    for _round in 0..ROUNDS {
        let task = task();
        let old = namespace();
        let old_id = old.id();
        assert!(task.replace_network_namespace(old).is_ok());
        let replacement = namespace();
        let replacement_id = replacement.id();
        let start = Arc::new(Barrier::new(3));

        let replacing_task = Arc::clone(&task);
        let replacing_start = Arc::clone(&start);
        let replacer = std::thread::spawn(move || {
            replacing_start.wait();
            if let Err(unused) = replacing_task.replace_network_namespace(replacement) {
                drop(unused);
            }
        });
        let releasing_task = Arc::clone(&task);
        let releasing_start = Arc::clone(&start);
        let releaser = std::thread::spawn(move || {
            releasing_start.wait();
            releasing_task.release_network_namespace();
        });
        start.wait();
        replacer.join().unwrap();
        releaser.join().unwrap();

        assert!(task.network_namespace_snapshot().is_none(),
            "release must be terminal regardless of lock acquisition order");
        assert!(lookup(old_id).is_none());
        assert!(lookup(replacement_id).is_none());
        let dead = take_dead_namespace_ids();
        assert_eq!(dead.iter().filter(|id| **id == old_id).count(), 1);
        assert_eq!(dead.iter().filter(|id| **id == replacement_id).count(), 1);
        finish_claimed(&dead);
    }
}

#[test]
fn final_task_owner_drop_is_claimed_once_by_racing_harvesters() {
    const HARVESTERS: usize = 8;
    let _guard = test_lock();
    install_callback();
    let task = task();
    let namespace = namespace();
    let id = namespace.id();
    assert!(task.replace_network_namespace(namespace).is_ok());
    let snapshot = task.network_namespace_snapshot().expect("task owner snapshot");
    task.release_network_namespace();

    let live_start = Arc::new(Barrier::new(HARVESTERS));
    let mut live_harvesters = std::vec::Vec::new();
    for _ in 0..HARVESTERS {
        let start = Arc::clone(&live_start);
        live_harvesters.push(std::thread::spawn(move || {
            start.wait();
            take_dead_namespace_ids()
        }));
    }
    let live_claims = live_harvesters.into_iter().flat_map(|thread| thread.join().unwrap())
        .filter(|claimed| *claimed == id).count();
    assert_eq!(live_claims, 0, "snapshot owner must exclude teardown claim");
    assert_eq!(lookup(id).unwrap().id(), id);

    drop(snapshot);
    let dead_start = Arc::new(Barrier::new(HARVESTERS));
    let mut dead_harvesters = std::vec::Vec::new();
    for _ in 0..HARVESTERS {
        let start = Arc::clone(&dead_start);
        dead_harvesters.push(std::thread::spawn(move || {
            start.wait();
            take_dead_namespace_ids()
        }));
    }
    let claimed: std::vec::Vec<_> = dead_harvesters.into_iter()
        .flat_map(|thread| thread.join().unwrap()).collect();
    assert_eq!(claimed.iter().filter(|claimed_id| **claimed_id == id).count(), 1);
    assert!(lookup(id).is_none(), "claimed namespace cannot be repinned");
    finish_claimed(&claimed);
    assert!(!finish_teardown(id), "finished namespace cannot be claimed twice");
}
