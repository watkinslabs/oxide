//! Namespace isolation of keys, ids and teardown.

use syscall::errno::Errno;

use super::super::super::limits::{GETVAL, IPC_CREAT, SETVAL};
use super::super::{model, semctl_in, semget_in};
use super::common::{ns, reset, root, TEST_LOCK};

#[test]
fn the_same_key_names_a_different_set_in_each_namespace() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (a, b, c) = (ns(), ns(), root());
    let ia = semget_in(a, &c, 99, 1, IPC_CREAT | 0o600).unwrap();
    let ib = semget_in(b, &c, 99, 1, IPC_CREAT | 0o600).unwrap();

    assert_eq!(semctl_in(a, &c, ia, 0, SETVAL, 3), Ok(0));
    assert_eq!(semctl_in(b, &c, ib, 0, GETVAL, 0), Ok(0),
        "the other namespace's set is untouched even at the same key and id");
    assert_eq!(semctl_in(a, &c, ia, 0, GETVAL, 0), Ok(3));
}

#[test]
fn an_id_from_one_namespace_is_invisible_in_another() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (a, b, c) = (ns(), ns(), root());
    let ia = semget_in(a, &c, 1, 1, IPC_CREAT | 0o600).unwrap();
    // b's space is empty, so a's id resolves to nothing there.
    assert_eq!(semctl_in(b, &c, ia, 0, GETVAL, 0), Err(Errno::Einval));
    assert!(model::lookup_checked(b, ia).is_none());
    assert!(model::lookup_checked(a, ia).is_some());
    // The key lookup is namespace-scoped too.
    assert_eq!(semget_in(b, &c, 1, 1, 0o600), Err(Errno::Enoent));
}

#[test]
fn reaping_a_namespace_drops_only_its_own_sets() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (a, b, c) = (ns(), ns(), root());
    let ia = semget_in(a, &c, 5, 2, IPC_CREAT | 0o600).unwrap();
    let ib = semget_in(b, &c, 5, 2, IPC_CREAT | 0o600).unwrap();
    let set_a = model::lookup_checked(a, ia).unwrap();

    model::reap_namespace(a);
    assert!(model::lookup_checked(a, ia).is_none());
    assert!(set_a.state.lock().removed, "a parked waiter is unwound with EIDRM");
    assert_eq!(semctl_in(b, &c, ib, 0, GETVAL, 0), Ok(0), "the peer namespace survives");
}
