// The wait(2) family ACROSS a pid-namespace boundary: which child a request
// selects, and which number the reply carries, decided by the READER's
// namespace rather than by an internal tid.
//
// This suite could not exist before: `registry::reader_pid_ns` was hard-coded
// to the initial namespace in every non-kernel build, so a hosted test that
// nested namespaces and installed a reader inside one still got the initial
// namespace's answers, and no assertion here could have failed. That is why
// rows 61/247 carried "nested PID-namespace differential coverage" as a gap
// with no defect named — the check was structurally unable to run, not absent
// by oversight.

extern crate std;

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use namespace_identity::{allocate, initial, NamespaceKind, NamespaceRef};

use super::common::registry_test_lock;
use crate::live::runqueue::{self, Runqueue};
use crate::registry;
use crate::task::{SchedClass, Task};

/// `wait4(-1)`: any child.
const ANY_CHILD: i32 = -1;
/// A waiter's process group, only reached by the `pid == 0` form.
const WAITER_PGID: u32 = 0;
/// No `__WALL` / `__WCLONE` / `__WNOTHREAD`.
const NO_OPTIONS: u64 = 0;

fn nested(parent: &NamespaceRef) -> NamespaceRef {
    allocate(NamespaceKind::Pid, initial(NamespaceKind::User), Some(parent.clone())).unwrap()
}

/// A registered process leader living in `ns`, numbered by `ns` and by every
/// ancestor of it.
fn leader(tid: u32, ns: &NamespaceRef) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "waitns", SchedClass::Normal { weight: 1024 }));
    assert!(task.replace_namespace(ns.clone()).is_ok());
    task.tgid.store(tid, Ordering::Release);
    task.exit_signal.store(crate::Signum::Sigchld as u8, Ordering::Release);
    task.alloc_pid_mappings(&[], true).unwrap();
    registry::insert(&task);
    task
}

/// Publish `reader` as the running task, which is what makes every number
/// below render in `reader`'s pid namespace.
/// # SAFETY: test-only, serialized by `registry_test_lock`.
fn install_reader(reader: &Arc<Task>) {
    let idle = Arc::new(Task::new(0xFFFF_0001, "idle", SchedClass::Idle));
    unsafe { runqueue::install_global(Runqueue::new(0, idle)); }
    let rq = runqueue::global().expect("just installed");
    let _ = unsafe { rq.swap_current(Arc::clone(reader)) };
}

fn uninstall() { unsafe { runqueue::uninstall_global(); } }

/// A stopped child with a pending job-control stop for its parent to collect.
fn stop(child: &Arc<Task>, code: u32) {
    child.stop_code.store(code, Ordering::Release);
    child.stop_pending.store(true, Ordering::Release);
}

/// Build parent + child inside a nested namespace and return
/// `(parent, child, child's number as the nested namespace sees it)`.
fn nested_pair(parent_tid: u32, child_tid: u32) -> (Arc<Task>, Arc<Task>, u32) {
    let inner = nested(&initial(NamespaceKind::Pid));
    let parent = leader(parent_tid, &inner);
    let child = leader(child_tid, &inner);
    child.parent_tid.store(parent.tid, Ordering::Release);
    let inner_number = registry::tgid_nr_in(&child, &inner).expect("numbered by its own ns");
    (parent, child, inner_number)
}

/// The number a nested reader must pass to `waitpid` is its OWN namespace's,
/// and that is the number the selector matches.
#[test]
fn a_nested_reader_selects_its_child_by_the_number_its_namespace_gives_it() {
    let _g = registry_test_lock();
    registry::clear_for_tests();
    let (parent, child, inner_number) = nested_pair(0x7400, 0x7401);
    let outer_number = registry::tgid_nr_in(&child, &initial(NamespaceKind::Pid)).unwrap();
    assert_ne!(inner_number, outer_number,
        "the nest must actually renumber, or this suite proves nothing");
    stop(&child, crate::Signum::Sigstop as u32);

    install_reader(&parent);
    let hit = registry::child_stop_event(parent.tid, parent.tid, inner_number as i32,
        WAITER_PGID, NO_OPTIONS, true, false, false);
    let (snapshot, _, _) = hit.expect("its own namespace's number selects the child");
    assert_eq!(snapshot.vpid, inner_number, "and the reply carries that number back");

    // The number the INITIAL namespace uses names nothing from in here.
    assert!(registry::child_stop_event(parent.tid, parent.tid, outer_number as i32,
        WAITER_PGID, NO_OPTIONS, true, false, false).is_none(),
        "an outer number must not select a child from inside the nest");
    uninstall();
}

/// The same child, read from the initial namespace, answers with the initial
/// namespace's number — one task, two numbers, each correct for its reader.
#[test]
fn the_same_child_reports_a_different_number_to_an_outer_reader() {
    let _g = registry_test_lock();
    registry::clear_for_tests();
    let (parent, child, inner_number) = nested_pair(0x7410, 0x7411);
    let outer_number = registry::tgid_nr_in(&child, &initial(NamespaceKind::Pid)).unwrap();
    stop(&child, crate::Signum::Sigstop as u32);

    // An outer reader adopting the child: same task, outer numbering.
    let outer_parent = leader(0x7412, &initial(NamespaceKind::Pid));
    child.parent_tid.store(outer_parent.tid, Ordering::Release);
    install_reader(&outer_parent);
    let (snapshot, _, _) = registry::child_stop_event(outer_parent.tid, outer_parent.tid,
        ANY_CHILD, WAITER_PGID, NO_OPTIONS, true, false, false)
        .expect("the child is waitable from outside too");
    assert_eq!(snapshot.vpid, outer_number);
    assert_ne!(snapshot.vpid, inner_number);
    uninstall();
    let _ = parent;
}

/// A reader in a SIBLING namespace can name the child at all — the walk finds
/// no number, and `wait4` must not hand it somebody else's child.
#[test]
fn a_sibling_namespace_reader_matches_no_child() {
    let _g = registry_test_lock();
    registry::clear_for_tests();
    let root = initial(NamespaceKind::Pid);
    let a = nested(&root);
    let b = nested(&root);
    let parent = leader(0x7420, &a);
    let child = leader(0x7421, &a);
    child.parent_tid.store(parent.tid, Ordering::Release);
    stop(&child, crate::Signum::Sigstop as u32);

    // A task in `b` claiming to be the parent: even with the parent link
    // forged, `b` numbers the child nowhere, so no pid form can name it.
    let stranger = leader(0x7422, &b);
    child.parent_tid.store(stranger.tid, Ordering::Release);
    install_reader(&stranger);
    let named = registry::tgid_nr_in(&child, &b);
    assert_eq!(named, None, "a sibling namespace numbers nothing of `a`'s");
    let (snapshot, _, _) = registry::child_stop_event(stranger.tid, stranger.tid,
        ANY_CHILD, WAITER_PGID, NO_OPTIONS, true, false, false)
        .expect("the parent link still selects it");
    assert_eq!(snapshot.vpid, 0,
        "an unnameable child reports 0, never another namespace's number");
    uninstall();
}

/// Zombie reaping answers in the reader's namespace the same way the stop path
/// does — the two must not disagree, since a supervisor sees both.
#[test]
fn reaping_reports_the_readers_number_too() {
    let _g = registry_test_lock();
    registry::clear_for_tests();
    let inner = nested(&initial(NamespaceKind::Pid));
    let parent = leader(0x7430, &inner);
    let child = leader(0x7431, &inner);
    child.parent_tid.store(parent.tid, Ordering::Release);
    let inner_number = registry::tgid_nr_in(&child, &inner).unwrap();
    let outer_number = registry::tgid_nr_in(&child, &initial(NamespaceKind::Pid)).unwrap();
    assert_ne!(inner_number, outer_number);

    install_reader(&parent);
    let inner_view = crate::registry::WaitChildSnapshot::from_task(&child).vpid;
    uninstall();

    let outsider = leader(0x7432, &initial(NamespaceKind::Pid));
    install_reader(&outsider);
    let outer_view = crate::registry::WaitChildSnapshot::from_task(&child).vpid;
    uninstall();

    assert_eq!(inner_view, inner_number);
    assert_eq!(outer_view, outer_number);
}
