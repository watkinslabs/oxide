// pidfd lifetime under a concurrently disappearing pid namespace and a
// concurrent reap — the two lifetime boundaries `pidfd_open(2)` and
// `pidfd_getfd(2)` sit on, with the order between the pidfd holder and the
// teardown DECLARED rather than raced for.
//
// A pidfd deliberately outlives what it names: it retains the PID identity
// after the task is released, so poll can report the exit and `PIDFD_GET_INFO`
// can still answer. That retention is what makes the boundaries sharp. The
// identity holds only WEAK references to the namespaces that number it, so a
// namespace torn down under a live pidfd must make its level disappear rather
// than answer with a number nothing owns; and a reap must make the target
// unresolvable, because every `pidfd_getfd` ESRCH arm rests on exactly that.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use namespace_identity::{allocate, initial, NamespaceKind, NamespaceRef};

use super::common::registry_test_lock;
use super::interleave;
use crate::registry::{self, PidfdAcquireError, PidfdKind};
use crate::task::{SchedClass, Task, TaskState};

const TARGET_TID: u32 = 7500;
/// The target's number inside the nested namespace, and outside it.
const INNER_NR: u32 = 40;
const OUTER_NR: u32 = 7540;

fn nested_pid_ns() -> NamespaceRef {
    allocate(NamespaceKind::Pid, initial(NamespaceKind::User),
        Some(initial(NamespaceKind::Pid))).expect("nested pid namespace")
}

/// A leader inside `ns`, numbered in `ns` and in the initial namespace, and
/// published in the process table.
fn target_in(ns: &NamespaceRef) -> Arc<Task> {
    let t = Arc::new(Task::new(TARGET_TID, "pidfd-il", SchedClass::Normal { weight: 1024 }));
    assert!(t.replace_namespace(ns.clone()).is_ok());
    t.vtid.store(INNER_NR, Ordering::Release);
    t.vtgid.store(INNER_NR, Ordering::Release);
    t.configure_pid_mappings(&[INNER_NR, OUTER_NR]).expect("two-level numbering");
    registry::insert(&t);
    t
}

/// Drop every activation of `ns`: the test's own and the target's membership.
/// This is what the last member of a pid namespace exiting does.
fn tear_down(ns: NamespaceRef, target: &Arc<Task>) {
    interleave::point("ns:go");
    target.release_namespaces();
    drop(ns);
    interleave::point("ns:torn-down");
}

/// A pidfd holder walking the identity's namespace levels while the namespace
/// is torn down UNDER the walk. The level it already resolved stays coherent —
/// the pin it took keeps the namespace object alive for as long as it is
/// looking at it — and nothing in the walk observes a half-destroyed namespace.
///
/// Catches: a resolution that keeps a bare pointer or id across the seam
/// instead of a reference, which would read a namespace whose last owner has
/// gone.
#[test]
fn a_teardown_under_a_live_pidfd_walk_cannot_pull_the_level_out_from_under_it() {
    let _g = registry_test_lock();
    registry::clear_for_tests();
    let ns = nested_pid_ns();
    let target = target_in(&ns);
    let identity = registry::acquire_pidfd_in_namespace(&ns, INNER_NR, PidfdKind::Process)
        .expect("the pidfd names a live leader");
    let dead_id = ns.ns_id().as_u64();

    let schedule = interleave::schedule(&[
        ("reader",    "pidns:before-upgrade"),  // enters the innermost level
        ("reader",    "pidns:after-upgrade"),   // ...and has pinned it; parks here
        ("destroyer", "ns:go"),                 // teardown runs against that pin
        ("destroyer", "ns:torn-down"),
        ("reader",    "pidns:before-upgrade"),  // walk resumes on the next level
    ]);

    let walk = { let identity = Arc::clone(&identity);
        interleave::spawn("reader", move || identity.namespaces()) };
    let destroyer = { let target = Arc::clone(&target);
        interleave::spawn("destroyer", move || tear_down(ns, &target)) };
    let levels = walk.join().unwrap();
    destroyer.join().unwrap();
    schedule.assert_complete();

    let ids: Vec<u64> = levels.iter().map(|pin| pin.ns_id().as_u64()).collect();
    assert!(ids.contains(&dead_id),
        "a level resolved before the teardown stays readable through it");
    assert_eq!(levels.len(), 2, "both levels of the chain answered");
}

/// The mirror order: the namespace is gone before the pidfd holder looks. The
/// level must DISAPPEAR — a pidfd may not report a number in a namespace no
/// longer alive, because nothing owns that number any more and the next
/// namespace to be created can hand it out.
///
/// Catches: dropping the liveness test from namespace resolution, which makes
/// a torn-down namespace keep answering for as long as any weak holder exists.
#[test]
fn a_namespace_torn_down_before_the_walk_stops_numbering_the_pidfd() {
    let _g = registry_test_lock();
    registry::clear_for_tests();
    let ns = nested_pid_ns();
    let target = target_in(&ns);
    let identity = registry::acquire_pidfd_in_namespace(&ns, INNER_NR, PidfdKind::Process)
        .expect("the pidfd names a live leader");
    let dead_id = ns.ns_id().as_u64();

    let schedule = interleave::schedule(&[
        ("destroyer", "ns:go"),
        ("destroyer", "ns:torn-down"),
        ("reader",    "pidns:before-upgrade"),
    ]);

    let destroyer = { let target = Arc::clone(&target);
        interleave::spawn("destroyer", move || tear_down(ns, &target)) };
    let walk = { let identity = Arc::clone(&identity);
        interleave::spawn("reader", move || identity.namespaces()) };
    let levels = walk.join().unwrap();
    destroyer.join().unwrap();
    schedule.assert_complete();

    let ids: Vec<u64> = levels.iter().map(|pin| pin.ns_id().as_u64()).collect();
    assert!(!ids.contains(&dead_id),
        "a destroyed namespace must not keep numbering a retained identity");
    assert_eq!(levels.len(), 1, "only the initial namespace still numbers it");
    // The pidfd itself is unharmed: the identity is what it holds, and the
    // identity outliving its namespace is the whole point of the retention.
    assert!(!identity.reaped(), "losing a namespace is not a reap");
    assert!(identity.task().is_some(), "and does not release the task either");
}

/// `pidfd_getfd`'s first ESRCH arm is `identity.task()` returning nothing. This
/// is the order where the reap wins: by the time the holder resolves, the
/// target is released and there is nothing to fetch a descriptor from.
///
/// Catches: a reap that leaves the task reachable from the retained identity —
/// which would let a caller pull descriptors out of a process that has already
/// been waited for, and after PID reuse out of a DIFFERENT process.
#[test]
fn a_reap_before_the_holder_resolves_leaves_no_target() {
    let _g = registry_test_lock();
    registry::clear_for_tests();
    let ns = nested_pid_ns();
    let target = target_in(&ns);
    let identity = registry::acquire_pidfd_in_namespace(&ns, INNER_NR, PidfdKind::Process)
        .expect("the pidfd names a live leader");
    target.set_state(TaskState::Zombie);

    let schedule = interleave::schedule(&[
        ("reaper",   "reap:go"),
        ("reaper",   "reap:marked"),
        ("resolver", "getfd:go"),
        ("resolver", "getfd:resolved"),
    ]);

    let reaper = { let target = Arc::clone(&target); interleave::spawn("reaper", move || {
        interleave::point("reap:go");
        registry::mark_reaped(&target);
        interleave::point("reap:marked");
    }) };
    let resolver = { let identity = Arc::clone(&identity);
        interleave::spawn("resolver", move || {
            interleave::point("getfd:go");
            let resolved = identity.task();
            interleave::point("getfd:resolved");
            resolved
        }) };
    let resolved = resolver.join().unwrap();
    reaper.join().unwrap();
    schedule.assert_complete();

    assert!(resolved.is_none(), "a reaped target is not resolvable from its pidfd");
    assert!(identity.reaped(), "and the identity reports the hangup");
    assert!(matches!(
        registry::acquire_pidfd_in_namespace(&ns, INNER_NR, PidfdKind::Process),
        Err(PidfdAcquireError::NotFound)),
        "nor can a new pidfd be opened on it");
    drop(ns);
}

/// The mirror order: the holder resolves a target that is reaped an instant
/// later. Resolution alone must not be a licence to act — the state the second
/// gate reads has to be the CURRENT state, so the caller still lands on ESRCH
/// rather than fetching from a released process.
///
/// Catches: caching the target's liveness at resolution time, and any reap that
/// fails to publish the zombie state the second gate reads.
#[test]
fn a_reap_after_the_holder_resolves_still_closes_the_window() {
    let _g = registry_test_lock();
    registry::clear_for_tests();
    let ns = nested_pid_ns();
    let target = target_in(&ns);
    let identity = registry::acquire_pidfd_in_namespace(&ns, INNER_NR, PidfdKind::Process)
        .expect("the pidfd names a live leader");

    let schedule = interleave::schedule(&[
        ("resolver", "getfd:go"),
        ("resolver", "getfd:resolved"),
        ("reaper",   "reap:go"),
        ("reaper",   "reap:marked"),
        ("resolver", "getfd:acts"),
    ]);

    let resolver = { let identity = Arc::clone(&identity);
        interleave::spawn("resolver", move || {
            interleave::point("getfd:go");
            let resolved = identity.task().expect("the target is live at resolution");
            interleave::point("getfd:resolved");
            interleave::point("getfd:acts");
            (resolved.state(), resolved.reaped.load(Ordering::Acquire))
        }) };
    let reaper = { let target = Arc::clone(&target); interleave::spawn("reaper", move || {
        interleave::point("reap:go");
        target.set_state(TaskState::Zombie);
        registry::mark_reaped(&target);
        interleave::point("reap:marked");
    }) };
    let (state, reaped) = resolver.join().unwrap();
    reaper.join().unwrap();
    schedule.assert_complete();

    assert_eq!(state, TaskState::Zombie,
        "the gate after resolution reads the state the reap published");
    assert!(reaped, "and the release flag the reap set");
    assert!(identity.task().is_none(), "the identity no longer hands out the task");
    drop(ns);
}
