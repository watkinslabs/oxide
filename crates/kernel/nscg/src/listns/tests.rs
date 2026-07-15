use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::sync::mpsc::sync_channel;

use namespace_identity::NamespaceKind;

use super::*;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7100_0000);
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn task_with_uts() -> (Arc<sched::Task>, NamespaceRef) {
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);
    let task = Arc::new(sched::Task::new(tid, "listns-retain",
        sched::SchedClass::Normal { weight: 1024 }));
    let owner = namespace_identity::allocate(NamespaceKind::Uts,
        namespace_identity::initial(NamespaceKind::User), None).unwrap();
    assert!(task.replace_namespace(Arc::clone(&owner)).is_ok());
    sched::registry::insert(&task);
    (task, owner)
}

#[test]
fn snapshot_first_retains_owner_through_id_publication() {
    let _serial = TEST_LOCK.lock().unwrap();
    let (task, owner) = task_with_uts();
    let ino = owner.nsfs_ino();
    let weak = Arc::downgrade(&owner);
    let (snapshot_go_tx, snapshot_go_rx) = sync_channel(0);
    let (snapshot_tx, snapshot_rx) = sync_channel(0);
    let (drop_go_tx, drop_go_rx) = sync_channel(0);
    let (drop_done_tx, drop_done_rx) = sync_channel(0);

    std::thread::scope(|scope| {
        scope.spawn(move || {
            snapshot_go_rx.recv().unwrap();
            snapshot_tx.send(listns_snapshot(CLONE_NEWUTS as u32,
                ListNsOwnerFilter::All).unwrap()).unwrap();
        });
        scope.spawn(move || {
            drop_go_rx.recv().unwrap();
            drop(owner);
            task.release_namespaces();
            drop(task);
            drop_done_tx.send(()).unwrap();
        });

        snapshot_go_tx.send(()).unwrap();
        let snapshot = snapshot_rx.recv().unwrap();
        assert!(snapshot.first_after(ino - 1).is_some_and(|index| snapshot.id(index) == Some(ino)));
        drop_go_tx.send(()).unwrap();
        drop_done_rx.recv().unwrap();
        assert!(weak.upgrade().is_some(), "enumeration snapshot must retain exact owner");
        assert!(snapshot.first_after(ino - 1).is_some_and(|index| snapshot.id(index) == Some(ino)),
            "retained ID remains publishable after task release");
        drop(snapshot);
    });
    assert!(weak.upgrade().is_none(), "snapshot release permits final owner drop");
}

#[test]
fn final_drop_first_excludes_dead_owner_without_resurrection() {
    let _serial = TEST_LOCK.lock().unwrap();
    let (task, owner) = task_with_uts();
    let ino = owner.nsfs_ino();
    let id = owner.id();
    let weak = Arc::downgrade(&owner);
    let (drop_go_tx, drop_go_rx) = sync_channel(0);
    let (drop_done_tx, drop_done_rx) = sync_channel(0);
    let (snapshot_go_tx, snapshot_go_rx) = sync_channel(0);
    let (snapshot_tx, snapshot_rx) = sync_channel(0);

    std::thread::scope(|scope| {
        scope.spawn(move || {
            drop_go_rx.recv().unwrap();
            drop(owner);
            task.release_namespaces();
            drop(task);
            drop_done_tx.send(()).unwrap();
        });
        scope.spawn(move || {
            snapshot_go_rx.recv().unwrap();
            snapshot_tx.send(listns_snapshot(CLONE_NEWUTS as u32,
                ListNsOwnerFilter::All).unwrap()).unwrap();
        });

        drop_go_tx.send(()).unwrap();
        drop_done_rx.recv().unwrap();
        assert!(weak.upgrade().is_none());
        snapshot_go_tx.send(()).unwrap();
        let snapshot = snapshot_rx.recv().unwrap();
        assert!(!(0..snapshot.len()).any(|index| snapshot.id(index) == Some(ino)));
    });
    assert!(namespace_identity::lookup(NamespaceKind::Uts, id).is_none(),
        "final-drop-first enumeration must not reconstruct dead IDs");
}
