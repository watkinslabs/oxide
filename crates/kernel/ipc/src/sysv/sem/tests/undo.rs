//! `SEM_UNDO` accumulation, bounds and `exit_sem`.

use namespace_identity::NamespaceId;
use syscall::errno::Errno;

use super::super::super::limits::{
    GETVAL, IPC_PRIVATE, IPC_RMID, SEMAEM, SEMVMX, SEM_UNDO, SETALL, SETVAL,
};
use super::super::model::Sem;
use super::super::op::{perform_atomic_semop, Semop};
use super::super::{model, semctl_in, semget_in, semop_in, undo, Sembuf};
use super::common::{ns, reset, root, uptr, TEST_LOCK};

fn sop(num: u16, op: i16, flg: i16) -> Sembuf { Sembuf { sem_num: num, sem_op: op, sem_flg: flg } }

fn sem(val: i32) -> Sem { Sem { val, pid: 0, ncnt: 0, zcnt: 0 } }

/// Hosted `current_tgid()` reports 0 with no task installed.
const TGID: u32 = 0;

/// The hosted stand-in task's undo-list handle, created on first `SEM_UNDO` use.
fn cur() -> undo::UndoId {
    super::super::super::block::current_undo_slot().unwrap()
        .load(core::sync::atomic::Ordering::Acquire)
}

/// `exit_sem` for that stand-in task.
fn exit_current() {
    undo::exit_sem(super::super::super::block::current_undo_slot().unwrap(), TGID);
}

fn getval(ns: NamespaceId, id: i32, num: i32) -> i64 {
    semctl_in(ns, &root(), id, num, GETVAL, 0).unwrap()
}

fn poke(ns: NamespaceId, id: i32, num: usize, val: i32) {
    model::lookup_checked(ns, id).unwrap().state.lock().sems[num].val = val;
}

#[test]
fn semadj_is_the_negated_operation_and_accumulates() {
    let mut s = [sem(10)];
    let mut adj = [0i32];
    assert_eq!(perform_atomic_semop(&mut s, &[sop(0, -3, SEM_UNDO)], Some(&mut adj), 1),
        Semop::Done);
    assert_eq!(adj, [3], "undoing a -3 means restoring +3");
    assert_eq!(perform_atomic_semop(&mut s, &[sop(0, 2, SEM_UNDO)], Some(&mut adj), 1),
        Semop::Done);
    assert_eq!(adj, [1]);
    assert_eq!(s[0].val, 9);
}

#[test]
fn a_failed_batch_rolls_semadj_back_with_the_values() {
    let mut s = [sem(5), sem(0)];
    let mut adj = [0i32, 0];
    let ops = [sop(0, -1, SEM_UNDO), sop(1, -1, SEM_UNDO)];
    assert_eq!(perform_atomic_semop(&mut s, &ops, Some(&mut adj), 1), Semop::Block(1));
    assert_eq!(adj, [0, 0], "the first op's adjustment is undone with its value");
    assert_eq!(s[0].val, 5);
}

#[test]
fn exceeding_the_semadj_range_is_erange_and_changes_nothing() {
    let mut s = [sem(SEMVMX)];
    let mut adj = [SEMAEM];
    // The adjustment would become SEMAEM + 1.
    assert_eq!(perform_atomic_semop(&mut s, &[sop(0, -1, SEM_UNDO)], Some(&mut adj), 1),
        Semop::Fail(Errno::Erange));
    assert_eq!(adj, [SEMAEM]);
    assert_eq!(s[0].val, SEMVMX);

    // The lower bound is -(SEMAEM + 1) — `short`'s range — and is inclusive.
    let mut s = [sem(0)];
    let mut adj = [-SEMAEM];
    assert_eq!(perform_atomic_semop(&mut s, &[sop(0, 1, SEM_UNDO)], Some(&mut adj), 1),
        Semop::Done);
    assert_eq!(adj, [-SEMAEM - 1]);
    let mut adj = [-SEMAEM - 1];
    assert_eq!(perform_atomic_semop(&mut s, &[sop(0, 1, SEM_UNDO)], Some(&mut adj), 1),
        Semop::Fail(Errno::Erange));
}

#[test]
fn exit_sem_applies_the_registered_adjustment() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (ns, c) = (ns(), root());
    let id = semget_in(ns, &c, IPC_PRIVATE, 2, 0o600).unwrap();
    assert_eq!(semop_in(ns, &c, id, &[sop(0, 5, 0)], None), Ok(()));
    assert_eq!(semop_in(ns, &c, id, &[sop(0, -2, SEM_UNDO)], None), Ok(()));
    assert_eq!(getval(ns, id, 0), 3);
    assert_eq!(undo::semadj_snapshot(cur(), ns, id), Some(alloc::vec![2, 0]));

    exit_current();
    assert_eq!(getval(ns, id, 0), 5, "the process's decrement is given back");
    assert_eq!(undo::semadj_snapshot(cur(), ns, id), None, "the list is dropped");
    // Idempotent: a second exit has nothing to apply.
    exit_current();
    assert_eq!(getval(ns, id, 0), 5);
}

#[test]
fn exit_sem_clamps_at_zero_and_at_semvmx() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (ns, c) = (ns(), root());

    // Downward: an undo of -5 against a value of 1 would go negative.
    let low = semget_in(ns, &c, IPC_PRIVATE, 1, 0o600).unwrap();
    assert_eq!(semop_in(ns, &c, low, &[sop(0, 5, SEM_UNDO)], None), Ok(()));
    assert_eq!(undo::semadj_snapshot(cur(), ns, low), Some(alloc::vec![-5]));
    poke(ns, low, 0, 1);

    // Upward: an undo of +100 against SEMVMX - 1 would overflow the maximum.
    let high = semget_in(ns, &c, IPC_PRIVATE, 1, 0o600).unwrap();
    assert_eq!(semop_in(ns, &c, high, &[sop(0, 100, 0)], None), Ok(()));
    assert_eq!(semop_in(ns, &c, high, &[sop(0, -100, SEM_UNDO)], None), Ok(()));
    assert_eq!(undo::semadj_snapshot(cur(), ns, high), Some(alloc::vec![100]));
    poke(ns, high, 0, SEMVMX - 1);

    exit_current();
    assert_eq!(getval(ns, low, 0), 0, "clamped at 0, not driven negative");
    assert_eq!(getval(ns, high, 0), SEMVMX as i64, "clamped at SEMVMX");
}

#[test]
fn ipc_rmid_invalidates_the_undo_so_a_later_exit_is_a_no_op() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (ns, c) = (ns(), root());
    let a = semget_in(ns, &c, IPC_PRIVATE, 1, 0o600).unwrap();
    let b = semget_in(ns, &c, IPC_PRIVATE, 1, 0o600).unwrap();
    assert_eq!(semop_in(ns, &c, a, &[sop(0, 4, SEM_UNDO)], None), Ok(()));
    assert_eq!(semop_in(ns, &c, b, &[sop(0, 4, SEM_UNDO)], None), Ok(()));

    assert_eq!(semctl_in(ns, &c, a, 0, IPC_RMID, 0), Ok(0));
    assert_eq!(undo::semadj_snapshot(cur(), ns, a), None, "the removed set's entry is gone");
    assert!(undo::has_entry(cur(), ns, b), "an unrelated set keeps its entry");

    exit_current();
    assert_eq!(getval(ns, b, 0), 0, "b's own adjustment still applies");
}

#[test]
fn setval_and_setall_clear_pending_adjustments() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (ns, c) = (ns(), root());
    let id = semget_in(ns, &c, IPC_PRIVATE, 2, 0o600).unwrap();
    assert_eq!(semop_in(ns, &c, id, &[sop(0, 3, SEM_UNDO), sop(1, 4, SEM_UNDO)], None), Ok(()));
    assert_eq!(undo::semadj_snapshot(cur(), ns, id), Some(alloc::vec![-3, -4]));

    assert_eq!(semctl_in(ns, &c, id, 0, SETVAL, 9), Ok(0));
    assert_eq!(undo::semadj_snapshot(cur(), ns, id), Some(alloc::vec![0, -4]),
        "SETVAL zeroes only that semaphore's adjustment");

    let vals = [1u16, 1u16];
    assert_eq!(semctl_in(ns, &c, id, 0, SETALL, uptr(&vals)), Ok(0));
    assert_eq!(undo::semadj_snapshot(cur(), ns, id), Some(alloc::vec![0, 0]),
        "SETALL zeroes the whole array");
}

#[test]
fn a_fresh_undo_batch_reallocates_after_invalidation() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (ns, c) = (ns(), root());
    let id = semget_in(ns, &c, IPC_PRIVATE, 1, 0o600).unwrap();
    assert_eq!(semop_in(ns, &c, id, &[sop(0, 1, SEM_UNDO)], None), Ok(()));
    // Drop the entry the way freeary does, but leave the set published. A
    // fresh call re-allocates through find_alloc_undo, so the `un->semid == -1`
    // EIDRM branch is reachable only by an IPC_RMID landing INSIDE one call,
    // between its find_alloc and its set lock — a race no hosted test can stage.
    undo::invalidate_set(ns, id);
    assert!(!undo::has_entry(cur(), ns, id));
    assert_eq!(semop_in(ns, &c, id, &[sop(0, 1, SEM_UNDO)], None), Ok(()));
    assert_eq!(undo::semadj_snapshot(cur(), ns, id), Some(alloc::vec![-1]));
}

// --- CLONE_SYSVSEM sharing ---------------------------------------------------
//
// The list is shared by HANDLE and refcounted, so these drive `copy_semundo` /
// `exit_sem` against explicit handle slots — exactly what `Task::sysvsem_undo`
// is. Keying on the thread-group id instead made every one of these cases
// answer as though the flag were `CLONE_THREAD`.

use core::sync::atomic::{AtomicU64, Ordering};

use super::super::undo::{copy_semundo, get_undo_list, refs_for_test, NO_UNDO_LIST};

/// A registered adjustment on `slot`'s list for `id`, worth `+adj` on exit.
fn register(ns: NamespaceId, semid: i32, slot: &AtomicU64) -> undo::UndoId {
    let list = get_undo_list(slot).unwrap();
    undo::find_alloc(list, ns, semid, 1).unwrap();
    list
}

#[test]
fn a_plain_fork_child_starts_with_no_undo_list() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let parent = AtomicU64::new(0);
    let child = AtomicU64::new(0);
    let (ns, c) = (ns(), root());
    let id = semget_in(ns, &c, IPC_PRIVATE, 1, 0o600).unwrap();
    let list = register(ns, id, &parent);

    copy_semundo(false, &parent, &child).unwrap();
    assert_eq!(child.load(Ordering::Acquire), NO_UNDO_LIST,
        "fork(2) passes no CLONE_SYSVSEM, so the child inherits no adjustments");
    assert_eq!(refs_for_test(list), 1, "and takes no reference on the parent's");

    // The child exiting must therefore give nothing back.
    undo::exit_sem(&child, TGID);
    assert!(undo::has_entry(list, ns, id), "the parent still owes its adjustment");
}

#[test]
fn clone_sysvsem_shares_the_list_whether_or_not_it_is_a_thread() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let parent = AtomicU64::new(0);
    let child = AtomicU64::new(0);
    let (ns, c) = (ns(), root());
    let id = semget_in(ns, &c, IPC_PRIVATE, 1, 0o600).unwrap();
    let list = register(ns, id, &parent);

    // Nothing here says "thread": CLONE_SYSVSEM alone is what shares the list.
    copy_semundo(true, &parent, &child).unwrap();
    assert_eq!(child.load(Ordering::Acquire), list, "the same list, not a copy");
    assert_eq!(refs_for_test(list), 2);
}

#[test]
fn clone_sysvsem_from_a_parent_with_no_list_yet_creates_one_to_share() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let parent = AtomicU64::new(0);
    let child = AtomicU64::new(0);
    copy_semundo(true, &parent, &child).unwrap();
    let list = parent.load(Ordering::Acquire);
    assert_ne!(list, NO_UNDO_LIST, "the share forces the parent's list into being");
    assert_eq!(child.load(Ordering::Acquire), list);
    assert_eq!(refs_for_test(list), 2);
}

#[test]
fn the_adjustment_is_applied_only_when_the_last_sharer_exits() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let parent = AtomicU64::new(0);
    let child = AtomicU64::new(0);
    let (ns, c) = (ns(), root());
    let id = semget_in(ns, &c, IPC_PRIVATE, 1, 0o600).unwrap();
    // Take the semaphore with SEM_UNDO through the parent's handle.
    let list = get_undo_list(&parent).unwrap();
    undo::find_alloc(list, ns, id, 1).unwrap();
    undo::with_semadj(list, ns, id, |adj| adj.unwrap()[0] = 5);
    copy_semundo(true, &parent, &child).unwrap();

    // One sharer leaving releases nothing: the survivor is still using it.
    undo::exit_sem(&child, TGID);
    assert_eq!(getval(ns, id, 0), 0, "a surviving sharer still owes the adjustment");
    assert_eq!(refs_for_test(list), 1);
    assert_eq!(child.load(Ordering::Acquire), NO_UNDO_LIST);

    // The last one out applies it.
    undo::exit_sem(&parent, TGID);
    assert_eq!(getval(ns, id, 0), 5);
    assert_eq!(refs_for_test(list), 0, "and the list is gone");
}

#[test]
fn an_unshared_child_gives_its_own_adjustment_back_at_its_own_exit() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let parent = AtomicU64::new(0);
    let child = AtomicU64::new(0);
    let (ns, c) = (ns(), root());
    let id = semget_in(ns, &c, IPC_PRIVATE, 1, 0o600).unwrap();

    let plist = get_undo_list(&parent).unwrap();
    undo::find_alloc(plist, ns, id, 1).unwrap();
    undo::with_semadj(plist, ns, id, |adj| adj.unwrap()[0] = 3);
    copy_semundo(false, &parent, &child).unwrap();
    let clist = get_undo_list(&child).unwrap();
    assert_ne!(clist, plist, "no CLONE_SYSVSEM means a list of its own");
    undo::find_alloc(clist, ns, id, 1).unwrap();
    undo::with_semadj(clist, ns, id, |adj| adj.unwrap()[0] = 4);

    undo::exit_sem(&child, TGID);
    assert_eq!(getval(ns, id, 0), 4, "only the child's own adjustment");
    undo::exit_sem(&parent, TGID);
    assert_eq!(getval(ns, id, 0), 7);
}
