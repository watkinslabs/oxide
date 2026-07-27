//! `ipc_ids` identifier-space behaviour, per `ipc/util.c` `ipc_idr_alloc` /
//! `ipc_obtain_object_check` / `ipc_rmid`.

use super::*;
use namespace_identity::{allocate, NamespaceKind};

struct Obj { key: i32, seq: u16 }

fn ns_pair() -> (NamespaceId, NamespaceId) {
    let user = namespace_identity::initial(NamespaceKind::User);
    let a = allocate(NamespaceKind::Ipc, user.clone(), None).unwrap();
    let b = allocate(NamespaceKind::Ipc, user, None).unwrap();
    let ids = (a.id(), b.id());
    // Leak the refs: the ids must stay valid for the whole test.
    core::mem::forget(a);
    core::mem::forget(b);
    ids
}

fn add(ids: &mut IpcIds<Obj>, ns: NamespaceId, key: i32) -> i32 {
    let (idx, seq, id) = ids.alloc_idx(ns, 64).expect("space available");
    ids.install(ns, idx, Arc::new(Obj { key, seq }));
    id
}

#[test]
fn id_encodes_sequence_above_index() {
    let (ns, _) = ns_pair();
    let mut ids: IpcIds<Obj> = IpcIds::new();
    let id = add(&mut ids, ns, 7);
    assert_eq!(id & IPCMNI_IDX_MASK, 0, "first object lands in index 0");
    assert_eq!(id >> IPCMNI_SHIFT, 0, "first sequence is 0");
    assert!(ids.lookup_checked(ns, id, |o| o.seq).is_some());
}

/// Drive the space into the state where the next allocation must wrap back to
/// a low index: allocation is cyclic within a window that GROWS with `in_use`,
/// so a purely growing space never wraps (`ipc_idr_alloc`). Only after enough
/// removals does the window shrink below the cursor, and that wrap is what
/// bumps `seq`. Returns every id handed out, indexed by slot.
fn fill_then_free(ids: &mut IpcIds<Obj>, ns: NamespaceId) -> Vec<i32> {
    let issued: Vec<i32> = (0..20).map(|i| add(ids, ns, i)).collect();
    for id in issued.iter().take(IPC_MIN_CYCLE) { ids.remove(ns, *id).expect("removable"); }
    issued
}

#[test]
fn a_stale_id_whose_slot_was_recycled_is_rejected() {
    let (ns, _) = ns_pair();
    let mut ids: IpcIds<Obj> = IpcIds::new();
    let issued = fill_then_free(&mut ids, ns);
    let stale = issued[4];
    assert!(ids.lookup_checked(ns, stale, |o| o.seq).is_none(), "a removed id does not resolve");
    let reused = add(&mut ids, ns, 999);
    assert_eq!(reused & IPCMNI_IDX_MASK, stale & IPCMNI_IDX_MASK, "the freed index is reused");
    assert_ne!(reused, stale, "but with a fresh sequence, so the id differs");
    assert!(ids.lookup_checked(ns, stale, |o| o.seq).is_none(),
        "ipc_checkid rejects the stale id even though its slot is live again");
    assert_eq!(ids.lookup_checked(ns, reused, |o| o.seq).unwrap().key, 999);
}

#[test]
fn a_growing_space_never_recycles_an_index() {
    let (ns, _) = ns_pair();
    let mut ids: IpcIds<Obj> = IpcIds::new();
    // The cyclic window is `max(in_use*3/2, 16)`, which always exceeds the
    // number allocated so far, so ids stay strictly increasing while nothing
    // is removed and `seq` stays 0.
    let issued: Vec<i32> = (0..40).map(|i| add(&mut ids, ns, i)).collect();
    for (i, id) in issued.iter().enumerate() {
        assert_eq!(*id, i as i32, "index {i} allocated in order with sequence 0");
    }
}

#[test]
fn stat_lookup_by_index_ignores_the_sequence_half() {
    let (ns, _) = ns_pair();
    let mut ids: IpcIds<Obj> = IpcIds::new();
    let issued = fill_then_free(&mut ids, ns);
    let reused = add(&mut ids, ns, 4242);
    let idx = reused & IPCMNI_IDX_MASK;
    assert_ne!(reused >> IPCMNI_SHIFT, 0, "sequence advanced on wrap");
    assert_ne!(reused, issued[idx as usize], "so the recycled slot has a new id");
    // *_STAT addresses raw indices, so the index resolves to whatever lives
    // there now regardless of sequence — that is exactly what `ipcs` walks.
    assert_eq!(ids.lookup_idx(ns, idx).unwrap().key, 4242);
    assert!(ids.lookup_idx(ns, 9_999).is_none());
    assert!(ids.lookup_idx(ns, -1).is_none());
}

#[test]
fn namespaces_do_not_share_keys_ids_or_indices() {
    let (a, b) = ns_pair();
    let mut ids: IpcIds<Obj> = IpcIds::new();
    let ida = add(&mut ids, a, 55);
    let idb = add(&mut ids, b, 55);
    assert_eq!(ida, idb, "each namespace indexes from 0, so the same id exists in both");
    // Same key, same id, different object: the namespace selects which.
    assert_eq!(ids.lookup_key(a, 55, |o| o.key).unwrap().key, 55);
    assert_eq!(ids.lookup_key(b, 55, |o| o.key).unwrap().key, 55);
    assert!(!Arc::ptr_eq(
        &ids.lookup_checked(a, ida, |o| o.seq).unwrap(),
        &ids.lookup_checked(b, idb, |o| o.seq).unwrap()));
    let only_a = add(&mut ids, a, 77);
    assert!(ids.lookup_key(b, 77, |o| o.key).is_none(), "key lookup does not cross namespaces");
    assert!(ids.lookup_checked(b, only_a, |o| o.seq).is_none(),
        "an id valid in one namespace does not resolve in another");
    assert_eq!(ids.in_use(a), 2);
    assert_eq!(ids.in_use(b), 1);
    assert_eq!(ids.all(a).len(), 2);
    assert_eq!(ids.all(b).len(), 1);
}

#[test]
fn ipc_private_never_matches_a_key_lookup() {
    let (ns, _) = ns_pair();
    let mut ids: IpcIds<Obj> = IpcIds::new();
    add(&mut ids, ns, super::super::limits::IPC_PRIVATE);
    assert!(ids.lookup_key(ns, super::super::limits::IPC_PRIVATE, |o| o.key).is_none());
    assert_eq!(ids.in_use(ns), 1, "the unkeyed object still exists, it is just unfindable by key");
}

#[test]
fn max_idx_tracks_the_highest_live_slot_and_retreats_on_removal() {
    let (ns, _) = ns_pair();
    let mut ids: IpcIds<Obj> = IpcIds::new();
    assert_eq!(ids.max_idx(ns), -1, "an empty space reports -1, which the ctl paths map to 0");
    let a = add(&mut ids, ns, 1);
    let b = add(&mut ids, ns, 2);
    let c = add(&mut ids, ns, 3);
    assert_eq!(ids.max_idx(ns), 2);
    ids.remove(ns, c).unwrap();
    assert_eq!(ids.max_idx(ns), 1);
    ids.remove(ns, b).unwrap();
    assert_eq!(ids.max_idx(ns), 0);
    ids.remove(ns, a).unwrap();
    assert_eq!(ids.max_idx(ns), -1);
    assert_eq!(ids.in_use(ns), 0);
}

#[test]
fn allocation_stops_at_the_class_limit() {
    let (ns, _) = ns_pair();
    let mut ids: IpcIds<Obj> = IpcIds::new();
    for i in 0..4 {
        let (idx, seq, _) = ids.alloc_idx(ns, 4).expect("under the limit");
        ids.install(ns, idx, Arc::new(Obj { key: i, seq }));
    }
    assert!(ids.alloc_idx(ns, 4).is_none(), "a full id space is ENOSPC, not a silent overwrite");
    let id = ids.all(ns)[0].key;
    ids.remove(ns, 0).unwrap();
    assert!(ids.alloc_idx(ns, 4).is_some(), "freeing a slot admits a new object");
    assert_eq!(id, 0);
}

#[test]
fn draining_a_namespace_yields_every_object_and_forgets_the_space() {
    let (a, b) = ns_pair();
    let mut ids: IpcIds<Obj> = IpcIds::new();
    for i in 0..3 { add(&mut ids, a, i); }
    add(&mut ids, b, 100);
    let drained = ids.drain_namespace(a);
    assert_eq!(drained.len(), 3);
    assert_eq!(ids.in_use(a), 0);
    assert_eq!(ids.max_idx(a), -1);
    assert_eq!(ids.in_use(b), 1, "an unrelated namespace is untouched");
}

#[test]
fn negative_ids_never_resolve() {
    let (ns, _) = ns_pair();
    let mut ids: IpcIds<Obj> = IpcIds::new();
    add(&mut ids, ns, 1);
    assert!(ids.lookup_checked(ns, -1, |o| o.seq).is_none());
    assert!(ids.lookup_checked(ns, i32::MIN, |o| o.seq).is_none());
}
