// `RLIMIT_NPROC` accounting against real tasks: the fork EAGAIN gate, the
// exit release, the `set*uid` charge transfer, and the deferred `execve`
// failure that gate arms.
//
// The counter table is process-global and entries vanish at zero, so each
// case uses its OWN uid and asserts absolute counts without needing a reset.

use core::sync::atomic::Ordering;

use namespace_identity::{allocate, initial, NamespaceKind};
use ucounts::{Counter, UcountKey};

use crate::cred::sys_setuid_on_for_tests as setuid_on;
use crate::rlimit::rlim;
use crate::task::{SchedClass, Task};
use crate::ucounts::{charge_task, execve_admits, fork_admits, nproc_limit,
    register_user_namespace, uncharge_task};

/// A task with the full capability set (the boot/root shape) owning `uid`.
fn task(uid: u32) -> Task {
    let t = Task::new(9000 + uid, "ucount-test", SchedClass::Normal { weight: 1024 });
    set_uid(&t, uid);
    t
}

fn set_uid(t: &Task, uid: u32) {
    t.creds.ruid.store(uid, Ordering::Release);
    t.creds.euid.store(uid, Ordering::Release);
    t.creds.suid.store(uid, Ordering::Release);
    t.creds.fsuid.store(uid, Ordering::Release);
}

fn drop_caps(t: &Task) {
    t.creds.cap_effective.store(0, Ordering::Release);
    t.creds.cap_permitted.store(0, Ordering::Release);
}

fn grant(t: &Task, cap: u32) {
    t.creds.cap_effective.store(1u64 << cap, Ordering::Release);
    t.creds.cap_permitted.store(1u64 << cap, Ordering::Release);
}

fn count(uid: u32) -> i64 { ucounts::value(UcountKey::new(0, uid), Counter::Nproc) }

fn set_nproc(t: &Task, limit: u64) { t.set_rlimit(rlim::NPROC, (limit, limit)); }

#[test]
fn a_charged_task_counts_against_its_account_and_releases_it_once() {
    const UID: u32 = 71_001;
    let t = task(UID);
    assert_eq!(count(UID), 0);
    charge_task(&t);
    assert_eq!(count(UID), 1);
    charge_task(&t);
    assert_eq!(count(UID), 1, "charging twice must not inflate the account");
    uncharge_task(&t);
    assert_eq!(count(UID), 0);
    uncharge_task(&t);
    assert_eq!(count(UID), 0, "releasing twice must not hand out free capacity");
}

#[test]
fn threads_of_one_process_each_count_because_rlimit_nproc_counts_tasks() {
    const UID: u32 = 71_002;
    let leader = task(UID);
    let worker = task(UID);
    charge_task(&leader);
    charge_task(&worker);
    assert_eq!(count(UID), 2);
    uncharge_task(&leader);
    uncharge_task(&worker);
}

#[test]
fn fork_is_refused_once_the_account_passes_its_limit() {
    const UID: u32 = 71_003;
    let parent = task(UID);
    drop_caps(&parent);
    set_nproc(&parent, 2);
    charge_task(&parent);

    let first = task(UID);
    drop_caps(&first);
    set_nproc(&first, 2);
    charge_task(&first);
    assert!(fork_admits(&first, &parent), "the second task is still at the limit");

    let third = task(UID);
    drop_caps(&third);
    set_nproc(&third, 2);
    charge_task(&third);
    assert!(!fork_admits(&third, &parent), "the third task passes it");
    uncharge_task(&third);

    assert!(fork_admits(&first, &parent), "releasing the refused task re-opens the door");
    uncharge_task(&first);
    uncharge_task(&parent);
}

#[test]
fn the_initial_namespaces_root_is_never_refused() {
    // A root fork bomb must not lock root out of its own recovery shell,
    // which is why Linux exempts INIT_USER outright.
    let parent = task(0);
    drop_caps(&parent);
    set_nproc(&parent, 1);
    let child = task(0);
    drop_caps(&child);
    set_nproc(&child, 1);
    charge_task(&parent);
    charge_task(&child);
    assert!(fork_admits(&child, &parent));
    uncharge_task(&parent);
    uncharge_task(&child);
}

#[test]
fn cap_sys_resource_and_cap_sys_admin_each_override_the_limit() {
    for cap in [crate::cap::SYS_RESOURCE, crate::cap::SYS_ADMIN] {
        let uid = 71_010 + cap;
        let parent = task(uid);
        grant(&parent, cap);
        set_nproc(&parent, 0);
        let child = task(uid);
        drop_caps(&child);
        set_nproc(&child, 0);
        charge_task(&child);
        assert!(fork_admits(&child, &parent), "cap {cap} must override the limit");
        uncharge_task(&child);
    }
}

#[test]
fn a_successful_fork_disarms_a_stale_deferred_failure() {
    const UID: u32 = 71_004;
    let parent = task(UID);
    drop_caps(&parent);
    set_nproc(&parent, 100);
    parent.nproc_exceeded.store(true, Ordering::Release);
    let child = task(UID);
    drop_caps(&child);
    set_nproc(&child, 100);
    charge_task(&child);
    assert!(fork_admits(&child, &parent));
    assert!(!parent.nproc_exceeded.load(Ordering::Acquire));
    uncharge_task(&child);
}

#[test]
fn setuid_moves_the_charge_to_the_new_account() {
    const FROM: u32 = 71_005;
    const TO: u32 = 71_006;
    let t = task(FROM);
    charge_task(&t);
    assert_eq!(count(FROM), 1);
    assert_eq!(setuid_on(&t, TO), 0);
    assert_eq!(count(FROM), 0, "the old account is released");
    assert_eq!(count(TO), 1, "the new account carries the task");
    uncharge_task(&t);
    assert_eq!(count(TO), 0);
}

#[test]
fn setuid_into_a_full_account_succeeds_but_arms_the_deferred_failure() {
    // Too much software ignores setuid(2)'s return value, so Linux reports
    // the overrun at the next execve instead of failing here.
    const OCCUPANT: u32 = 71_007;
    let squatter = task(OCCUPANT);
    charge_task(&squatter);

    let mover = task(71_008);
    set_nproc(&mover, 1);
    charge_task(&mover);
    assert_eq!(setuid_on(&mover, OCCUPANT), 0, "setuid never fails on quota");
    assert_eq!(count(OCCUPANT), 2);
    assert!(mover.nproc_exceeded.load(Ordering::Acquire), "the execve failure is armed");
    assert!(!execve_admits(&mover), "and the next execve refuses");

    // Once the account drops back under the limit the exec is let through
    // and the flag is dropped, so a transient overrun is not permanent.
    uncharge_task(&squatter);
    assert!(execve_admits(&mover));
    assert!(!mover.nproc_exceeded.load(Ordering::Acquire));
    uncharge_task(&mover);
}

#[test]
fn an_unarmed_task_never_pays_for_a_full_account() {
    const UID: u32 = 71_009;
    let a = task(UID);
    let b = task(UID);
    set_nproc(&b, 1);
    charge_task(&a);
    charge_task(&b);
    assert!(execve_admits(&b), "the flag, not the count, is what refuses an exec");
    uncharge_task(&a);
    uncharge_task(&b);
}

#[test]
fn setuid_that_does_not_move_the_real_uid_leaves_the_charge_alone() {
    const UID: u32 = 71_020;
    let t = task(UID);
    drop_caps(&t);
    charge_task(&t);
    // Without CAP_SETUID only the effective uid moves, and the charge is
    // keyed on the REAL uid, so the account must not change.
    t.creds.suid.store(UID + 1, Ordering::Release);
    assert_eq!(setuid_on(&t, UID + 1), 0);
    assert_eq!(count(UID), 1);
    assert_eq!(count(UID + 1), 0);
    uncharge_task(&t);
}

#[test]
fn a_task_in_a_new_user_namespace_still_charges_its_creator() {
    // The escape this closes: unshare(CLONE_NEWUSER) must not zero a uid's
    // process count.
    const UID: u32 = 71_030;
    let creator = task(UID);
    charge_task(&creator);
    assert_eq!(count(UID), 1);

    let init = initial(NamespaceKind::User);
    let ns = allocate(NamespaceKind::User, init.clone(), Some(init)).unwrap();
    register_user_namespace(&creator, ns.id().as_u64());

    let inside = task(0);
    assert!(inside.replace_namespace(ns.clone()).is_ok());
    charge_task(&inside);
    assert_eq!(count(UID), 2, "the namespaced task still charges its creator's account");
    assert_eq!(ucounts::value(UcountKey::new(ns.id().as_u64(), 0), Counter::Nproc), 1);

    uncharge_task(&inside);
    assert_eq!(count(UID), 1);
    uncharge_task(&creator);
}

#[test]
fn a_dying_task_releases_the_account_it_was_charged_in_not_the_one_it_ends_in() {
    // Namespace membership is dropped before a task reaches its terminal
    // state, so the account has to be latched at charge time. Recomputing it
    // at release would credit the wrong account and leak the real one.
    const UID: u32 = 71_040;
    let creator = task(UID);
    let init = initial(NamespaceKind::User);
    let ns = allocate(NamespaceKind::User, init.clone(), Some(init)).unwrap();
    register_user_namespace(&creator, ns.id().as_u64());

    let t = task(0);
    assert!(t.replace_namespace(ns.clone()).is_ok());
    charge_task(&t);
    let inner = UcountKey::new(ns.id().as_u64(), 0);
    assert_eq!(ucounts::value(inner, Counter::Nproc), 1);

    t.release_namespaces();
    uncharge_task(&t);
    assert_eq!(ucounts::value(inner, Counter::Nproc), 0, "released against the latched account");
    assert_eq!(count(UID), 0);
}

#[test]
fn the_default_nproc_limit_is_readable_from_a_fresh_task() {
    let t = task(71_050);
    assert_eq!(nproc_limit(&t), t.rlimit(rlim::NPROC).0);
}
