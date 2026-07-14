use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};
use std::sync::Arc;

use network_namespace::{allocate, initial, install_final_drop_callback, lookup};

use crate::{SchedClass, Task, TaskState};

static EXIT_TASK: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static DROP_STATE: AtomicU8 = AtomicU8::new(u8::MAX);

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

#[test]
fn task_namespace_slot_snapshots_replaces_and_releases_owners() {
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
    install_final_drop_callback(observe_final_drop).unwrap();
    DROP_STATE.store(u8::MAX, Ordering::Release);

    let task = task();
    let namespace = allocate(73).unwrap();
    let id = namespace.id();
    assert!(task.replace_network_namespace(namespace).is_ok());
    EXIT_TASK.store(Arc::as_ptr(&task) as *mut Task, Ordering::Release);

    task.mark_done();

    assert_eq!(DROP_STATE.load(Ordering::Acquire), TaskState::Runnable as u8);
    assert_eq!(task.state(), TaskState::Zombie);
    assert!(task.network_namespace_snapshot().is_none());
    assert!(lookup(id).is_none(), "pidfd-style task pin must not retain namespace");
    EXIT_TASK.store(ptr::null_mut(), Ordering::Release);
}
