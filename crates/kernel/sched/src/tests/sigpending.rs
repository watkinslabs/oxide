// `RLIMIT_SIGPENDING`: the per-user count of queued signal records.
//
// The property under test is SYMMETRY. A charge that outlives its record turns
// into a process that can never queue another real-time signal, and one that is
// released twice hands out capacity that was never freed — both silent. Every
// test here therefore drives a mutation sequence and asserts the account
// returns to exactly zero, including the paths that free records without any
// explicit release call (thread-group teardown, task exit).

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use ucounts::{Counter, UcountKey};

use crate::rlimit::rlim;
use crate::signum::{self, Signum};
use crate::sigqueue::Charge;
use crate::sigsend::SigSource;
use crate::task::{SchedClass, SigInfo, Task};

const SIGRTMIN: u32 = signum::RT_SIGNAL_MIN;
const SIGUSR1: u32 = Signum::Sigusr1 as u32;

/// Queued records charged to uid `uid` of the initial user namespace.
fn queued(uid: u32) -> i64 { ucounts::value(UcountKey::new(0, uid), Counter::Sigpending) }

/// A task whose `RLIMIT_SIGPENDING` charges land on a private account, so tests
/// never contend for one counter. `charge_task` is what latches the account on
/// the task (Linux `set_cred_ucounts`).
fn task(tid: u32, uid: u32) -> Arc<Task> {
    let t = Arc::new(Task::new(tid, "sigp", SchedClass::Normal { weight: 1024 }));
    t.creds.ruid.store(uid, Ordering::Release);
    crate::ucounts::charge_task(&t);
    t.set_rlimit(rlim::SIGPENDING, (8, 8));
    t
}

fn info(signo: u32, value: u64) -> SigInfo {
    SigInfo { signo, code: signum::SI_QUEUE, pid: 7, uid: 0, value, sys: None, fault: None, poll: None }
}

/// The charge a process-context send builds, `override_rlimit` included.
fn charge(t: &Task, rec: &SigInfo) -> Charge {
    t.sigq_charge(crate::sigsend::override_rlimit(rec.signo, &SigSource::Info(*rec)))
}

fn push(t: &Task, rec: SigInfo) -> bool { let c = charge(t, &rec); t.sigq_push(rec, c) }

fn push_shared(t: &Task, rec: SigInfo) -> bool {
    let c = charge(t, &rec);
    t.thread_group.post_shared_record(rec, c)
}

// --- symmetry ---------------------------------------------------------------

#[test]
fn a_dequeued_record_releases_its_slot() {
    const UID: u32 = 81_001;
    let t = task(1, UID);
    assert_eq!(queued(UID), 0);
    for n in 0..4 { assert!(push(&t, info(SIGRTMIN, n))); }
    assert_eq!(queued(UID), 4);
    for _ in 0..4 { assert!(t.sigq_pop(SIGRTMIN).0.is_some()); }
    assert_eq!(queued(UID), 0, "every dequeue releases exactly one slot");
}

#[test]
fn a_flushed_queue_releases_every_slot_it_held() {
    const UID: u32 = 81_002;
    let t = task(2, UID);
    for n in 0..5 { assert!(push(&t, info(SIGRTMIN, n))); }
    assert_eq!(queued(UID), 5);
    t.flush_pending_signal(SIGRTMIN as usize);
    assert_eq!(queued(UID), 0, "flush_sigqueue_mask frees the records, not just the bit");
}

#[test]
fn a_task_that_exits_with_records_still_queued_releases_them() {
    // Nothing calls a release here: the account settles because dropping the
    // task drops its queue array, and each record releases in `Drop`.
    const UID: u32 = 81_003;
    let t = task(3, UID);
    for n in 0..6 { assert!(push(&t, info(SIGRTMIN, n))); }
    assert_eq!(queued(UID), 6);
    crate::ucounts::uncharge_task(&t);
    drop(t);
    assert_eq!(queued(UID), 0, "a task exiting with queued records must not leak its slots");
}

#[test]
fn a_thread_group_teardown_releases_the_shared_queue() {
    const UID: u32 = 81_004;
    let t = task(4, UID);
    for n in 0..3 { assert!(push_shared(&t, info(SIGRTMIN, n))); }
    assert_eq!(queued(UID), 3);
    crate::ucounts::uncharge_task(&t);
    drop(t);
    assert_eq!(queued(UID), 0, "the process-wide set is accounted like the private one");
}

#[test]
fn a_refused_record_does_not_leak_the_charge_it_tested_with() {
    // The admission test charges FIRST and asks afterwards (Linux
    // `inc_rlimit_get_ucounts` then compare), so the refusal path has to undo
    // its own increment or the limit ratchets down to zero one send at a time.
    const UID: u32 = 81_005;
    let t = task(5, UID);
    t.set_rlimit(rlim::SIGPENDING, (2, 2));
    assert!(push(&t, info(SIGRTMIN, 1)));
    assert!(push(&t, info(SIGRTMIN, 2)));
    assert_eq!(queued(UID), 2);
    for n in 0..10 { assert!(!push(&t, info(SIGRTMIN, 100 + n))); }
    assert_eq!(queued(UID), 2, "ten refusals leave the account exactly where they found it");
    // …and the limit is still reachable after them.
    assert!(t.sigq_pop(SIGRTMIN).0.is_some());
    assert!(push(&t, info(SIGRTMIN, 3)), "a freed slot is usable again");
    assert_eq!(queued(UID), 2);
    for _ in 0..2 { t.sigq_pop(SIGRTMIN); }
    assert_eq!(queued(UID), 0);
}

#[test]
fn push_pop_churn_returns_the_account_to_zero() {
    const UID: u32 = 81_006;
    let t = task(6, UID);
    t.set_rlimit(rlim::SIGPENDING, (4, 4));
    let mut live = 0i64;
    for n in 0..200u64 {
        if n % 3 == 2 {
            if t.sigq_pop(SIGRTMIN).0.is_some() { live -= 1; }
        } else if push(&t, info(SIGRTMIN, n)) {
            live += 1;
        }
        assert_eq!(queued(UID), live, "the account tracks the queue exactly at step {n}");
        assert_eq!(t.sigq_len(SIGRTMIN) as i64, live);
    }
    while t.sigq_pop(SIGRTMIN).0.is_some() {}
    assert_eq!(queued(UID), 0);
}

// --- the limit still lets the un-droppable signals through -------------------

#[test]
fn a_task_at_its_limit_still_takes_a_signal_that_queues_no_record() {
    // `kill(2)` may not fail with EAGAIN. A bitmap-only signal carries no
    // record, so the limit has nothing to refuse.
    const UID: u32 = 81_007;
    let t = task(7, UID);
    t.set_rlimit(rlim::SIGPENDING, (1, 1));
    assert!(push(&t, info(SIGRTMIN, 1)));
    assert!(!push(&t, info(SIGRTMIN, 2)), "at the limit for records");
    t.thread_group.post_shared(SIGUSR1, None, Charge::Prealloc);
    assert_ne!(t.thread_group.shared_pending() & Signum::Sigusr1.bit(), 0,
        "a record-less send is delivered regardless of the limit");
    assert_eq!(queued(UID), 1);
    t.sigq_pop(SIGRTMIN);
    assert_eq!(queued(UID), 0);
}

#[test]
fn a_standard_signal_is_never_refused_by_the_limit() {
    // `legacy_queue` already caps standard signals at one record per signal, so
    // they hold no slot and a zero limit cannot silence them — SIGCHLD and
    // SIGTERM keep working on a process that has exhausted its budget.
    const UID: u32 = 81_008;
    let t = task(8, UID);
    t.set_rlimit(rlim::SIGPENDING, (0, 0));
    assert!(!push(&t, info(SIGRTMIN, 1)), "a zero limit queues no real-time record");
    assert!(push(&t, info(Signum::Sigterm as u32, 1)), "SIGTERM still carries its record");
    assert!(push(&t, info(Signum::Sigchld as u32, 1)));
    assert_eq!(queued(UID), 0, "standard records hold no slot");
    assert_eq!(t.sigq_len(Signum::Sigterm as u32), 1);
}

#[test]
fn an_irq_producers_record_is_never_charged() {
    // Linux's expiry path publishes a `SIGQUEUE_PREALLOC` record: no
    // allocation, no charge, and no account touched from hard-IRQ context.
    const UID: u32 = 81_009;
    let t = task(9, UID);
    t.sigq_reserve(SIGRTMIN);
    for n in 0..3 { assert!(t.sigq_push(info(SIGRTMIN, n), Charge::Prealloc)); }
    assert_eq!(queued(UID), 0);
    assert_eq!(t.sigq_len(SIGRTMIN), 3, "queued all the same");
    while t.sigq_pop(SIGRTMIN).0.is_some() {}
    assert_eq!(queued(UID), 0, "and releasing one touches no account either");
}

// --- which account -----------------------------------------------------------

#[test]
fn the_slot_is_charged_to_the_target_not_the_sender() {
    // Linux charges `sig_get_ucounts(t, ...)` and tests `task_rlimit(t, ...)`,
    // both of the TARGET. Charging the sender would let one user exhaust
    // another's budget, and would make a root sender's sends unbounded.
    const SENDER: u32 = 81_010;
    const TARGET: u32 = 81_011;
    let sender = task(10, SENDER);
    let target = task(11, TARGET);
    target.set_rlimit(rlim::SIGPENDING, (2, 2));
    for n in 0..2 { assert!(push(&target, info(SIGRTMIN, n))); }
    assert!(!push(&target, info(SIGRTMIN, 9)), "the TARGET's limit binds");
    assert_eq!(queued(TARGET), 2);
    assert_eq!(queued(SENDER), 0, "the sender's account is untouched");
    while target.sigq_pop(SIGRTMIN).0.is_some() {}
    assert_eq!(queued(TARGET), 0);
    drop(sender);
}

#[test]
fn a_record_releases_against_the_account_it_charged_across_a_setuid() {
    // Linux keeps the account ON the record (`q->ucounts`) and never migrates a
    // queued charge, so `set*uid` between the queue and the dequeue must leave
    // the ORIGINAL account settled and the new one untouched. Re-homing them
    // would credit a uid that never paid.
    const OLD: u32 = 81_012;
    const NEW: u32 = 81_013;
    let t = task(12, OLD);
    for n in 0..3 { assert!(push(&t, info(SIGRTMIN, n))); }
    assert_eq!(queued(OLD), 3);
    t.creds.ruid.store(NEW, Ordering::Release);
    crate::ucounts::recharge_after_setuid(&t);
    assert_eq!(queued(OLD), 3, "queued records stay charged where they were taken");
    assert_eq!(queued(NEW), 0);
    while t.sigq_pop(SIGRTMIN).0.is_some() {}
    assert_eq!(queued(OLD), 0, "and settle against that same account");
    assert_eq!(queued(NEW), 0);
    // A record queued AFTER the transition lands on the new account.
    assert!(push(&t, info(SIGRTMIN, 99)));
    assert_eq!(queued(NEW), 1);
    assert_eq!(queued(OLD), 0);
    t.sigq_pop(SIGRTMIN);
    assert_eq!(queued(NEW), 0);
}

#[test]
fn an_unlimited_task_queues_without_bound_but_still_accounts() {
    const UID: u32 = 81_014;
    let t = task(13, UID);
    t.set_rlimit(rlim::SIGPENDING, (crate::rlimit::INFINITY, crate::rlimit::INFINITY));
    for n in 0..64 { assert!(push(&t, info(SIGRTMIN, n))); }
    assert_eq!(queued(UID), 64, "RLIM_INFINITY removes the bound, not the accounting");
    while t.sigq_pop(SIGRTMIN).0.is_some() {}
    assert_eq!(queued(UID), 0);
}

#[test]
fn the_default_limit_is_the_linux_fork_init_value() {
    // `INIT_RLIMITS` leaves it at {0,0} and `fork_init` overwrites it with
    // `max_threads / 2`; leaving it RLIM_INFINITY would make the bound
    // unreachable and the real-time queue a memory-exhaustion path.
    let t = task(14, 81_015);
    assert_eq!(crate::rlimit::DEFAULT_RLIMITS[rlim::SIGPENDING],
               (crate::rlimit::DEFAULT_SIGPENDING, crate::rlimit::DEFAULT_SIGPENDING));
    assert_eq!(crate::rlimit::DEFAULT_SIGPENDING, crate::rlimit::THREADS_MAX / 2);
    assert_ne!(t.rlimit(rlim::SIGPENDING).0, crate::rlimit::INFINITY);
}
