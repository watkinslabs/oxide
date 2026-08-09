// `wait4`/`waitid` reap-vs-exit races, pinned to one order at a time.
//
// The wait family's hardest contract is not any single errno; it is that a
// reaper and an exiting child can be at any two points of their respective
// sequences at once, and the zombie must be neither lost (the parent blocks
// forever on a child that already exited) nor reaped twice (two waits both
// report a status for one child, and the child accounting that rides on the
// consuming arm runs twice).
//
// Every ordering below is DECLARED, not hoped for: `super::interleave` pins
// each actor's position in one global order, so the mirror of a case is a
// second schedule rather than a second run of the same test hoping for
// different luck.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::common::registry_test_lock;
use super::interleave;
use crate::exit::notify::SIG_IGN;
use crate::signum::Signum;
use crate::task::{SaHandler, SchedClass, Task};

const PARENT: u32 = 7400;
const CHILD:  u32 = 7401;
/// `exit(3)` — a status nothing else in the suite reports, so an assertion
/// cannot pass by reading another test's leftover zombie.
const STATUS: i32 = 3 << 8;
/// A distinctive fault count on the child, so a double reap shows up as double
/// accounting rather than as an equally plausible zero.
const CHILD_FAULTS: u64 = 5;

fn published(tid: u32) -> Arc<Task> {
    let t = Arc::new(Task::new(tid, "il", SchedClass::Normal { weight: 1024 }));
    t.exit_signal.store(Signum::Sigchld.as_u8(), Ordering::Release);
    t.vtgid.store(tid, Ordering::Release);
    crate::registry::insert(&t);
    t
}

/// A parent and one child of it, both in the process table, the child carrying
/// a known exit status and a known cost.
fn fixture() -> (Arc<Task>, Arc<Task>) {
    crate::registry::clear_for_tests();
    let p = published(PARENT);
    let c = published(CHILD);
    c.parent_tid.store(p.tid, Ordering::Release);
    c.set_parent_weak(Some(Arc::downgrade(&p)));
    c.set_pgid(p.pgid());
    c.exit_status.store(STATUS, Ordering::Release);
    for _ in 0..CHILD_FAULTS { crate::rusage_charge::fault(&c, false); }
    (p, c)
}

/// `wait4(-1, ..., 0)` issued by `p`, through the real reap path.
fn reap(p: &Arc<Task>) -> Option<(crate::registry::WaitChildSnapshot, i32)> {
    crate::live::reap_one(p.tid, p.tgid.load(Ordering::Acquire), -1, p.pgid(), 0)
}

/// The exiting child's own half of the exit path: retire from the thread group
/// (Linux `exit_notify` runs with `thread_group_empty(tsk)` already true), then
/// publish. Publishing without the retirement leaves the group non-empty, which
/// is the DEFERRED-leader case, not the exit this file is about.
fn exit(c: Arc<Task>) {
    let _ = c.thread_group.finish_exit(Arc::clone(&c));
    crate::live::enqueue_zombie(c);
    interleave::point("exit:end");
}

/// A real `SIGCHLD` handler on `p`. SIGCHLD's default action is to ignore, so a
/// parent that never installed one has nothing queued to observe — every
/// program this ordering protects (a shell reaping in its handler) installs one.
fn handle_sigchld(p: &Arc<Task>) {
    p.sigactions_ref().set_action(
        Signum::Sigchld.as_u8() as usize,
        Some(SaHandler { handler: 0x4000_1234, flags: 0, restorer: 0, mask: 0 }),
    ).expect("SIGCHLD is settable");
}

fn ignore_sigchld(p: &Arc<Task>) {
    p.sigactions_ref().set_action(
        Signum::Sigchld.as_u8() as usize,
        Some(SaHandler { handler: SIG_IGN, flags: 0, restorer: 0, mask: 0 }),
    ).expect("SIGCHLD is settable");
}

/// A reaper that arrives BEFORE the child is published sees nothing — and the
/// zombie must survive that miss. The guarantee is not that the reaper wins the
/// race but that losing it costs only a park: the publication that follows
/// leaves the child waitable, so the reaper's next look finds it with its real
/// status.
///
/// Catches: a publication path that treats "a reaper already looked" as
/// "nobody is waiting" and drops the zombie, and any exit path that stops
/// publishing once a reap has run against an empty list.
#[test]
fn a_reap_that_loses_the_race_to_publication_does_not_lose_the_zombie() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    let schedule = interleave::schedule(&[
        ("early",  "reap:entry"),          // the first look: nothing is published
        ("early",  "reap:done"),
        ("exiter", "exit:pre-publish"),    // now the exit path may publish
        ("exiter", "exit:notify-built"),   // published; the exiter parks here
        ("late",   "reap:entry"),          // the second look, in that window
        ("late",   "reap:done"),
        ("exiter", "exit:pre-wake"),
        ("exiter", "exit:end"),
    ]);

    let early = { let p = Arc::clone(&p); interleave::spawn("early", move || {
        let r = reap(&p);
        interleave::point("reap:done");
        r
    }) };
    let exiter = { let c = Arc::clone(&c); interleave::spawn("exiter", move || { exit(c); }) };
    let late = { let p = Arc::clone(&p); interleave::spawn("late", move || {
        let r = reap(&p);
        interleave::point("reap:done");
        r
    }) };
    assert!(early.join().unwrap().is_none(), "nothing is waitable before publication");
    let (child, status) = late.join().unwrap().expect("the published zombie is waitable");
    exiter.join().unwrap();

    schedule.assert_complete();
    assert_eq!(child.vpid, CHILD, "wait reports the child that exited");
    assert_eq!(status, STATUS, "and its exit status, not a default");
    assert!(!crate::live::zombies::has_zombies(PARENT), "the reap consumed it");
}

/// The mirror order: a reaper released between publication and the parent wake
/// must already see BOTH halves of the notification — the waitable zombie and
/// the queued SIGCHLD. The send is ordered ahead of the wake precisely so a
/// parent roused by the wake cannot reap, find no children left, and only then
/// receive a SIGCHLD with nothing behind it; a handler that re-waits on that
/// signal gets ECHILD and corrupts the shell's `$?`.
///
/// Catches: any reordering that moves the SIGCHLD send after the waiter wake,
/// or the publication after either.
#[test]
fn a_reap_released_at_the_wake_sees_both_the_zombie_and_the_sigchld() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    handle_sigchld(&p);
    let schedule = interleave::schedule(&[
        ("exiter", "exit:pre-publish"),
        ("exiter", "exit:pre-wake"),    // published and signalled; parked before the wake
        ("reaper", "reap:entry"),
        ("reaper", "reap:done"),
        ("exiter", "exit:end"),
    ]);

    let exiter = { let c = Arc::clone(&c); interleave::spawn("exiter", move || { exit(c); }) };
    let observed = { let p = Arc::clone(&p); interleave::spawn("reaper", move || {
        let reaped = reap(&p);
        let pending = crate::live::sigpend::shared_pending(&p);
        interleave::point("reap:done");
        (reaped, pending)
    }) };
    let (reaped, pending) = observed.join().unwrap();
    exiter.join().unwrap();

    schedule.assert_complete();
    let (child, status) = reaped.expect("the zombie is published before the wake");
    assert_eq!((child.vpid, status), (CHILD, STATUS));
    assert_ne!(pending & (1u64 << (Signum::Sigchld.as_u8() - 1)), 0,
        "SIGCHLD is queued before the wake, never after the reap that clears it");
}

/// SIGCHLD=SIG_IGN auto-reaps: POSIX leaves no waitable child at all, so a
/// concurrent `wait4` must find nothing. The dangerous implementation is
/// publish-then-remove, which is indistinguishable from this one in isolation
/// and wrong the instant a reaper runs in the window — it hands the parent a
/// status for a child that was never a zombie.
///
/// Catches: exactly that window. The reaper is released at the one point where
/// a published-then-removed child would be visible.
#[test]
fn an_autoreaped_child_is_never_visible_to_a_reaper_in_the_window() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    ignore_sigchld(&p);
    let schedule = interleave::schedule(&[
        ("exiter", "exit:pre-publish"),
        ("exiter", "exit:notify-built"),  // past the publish decision, before the release
        ("reaper", "reap:entry"),         // the reaper looks in exactly that window
        ("reaper", "reap:done"),
        ("exiter", "exit:pre-wake"),
        ("exiter", "exit:end"),
    ]);

    let exiter = { let c = Arc::clone(&c); interleave::spawn("exiter", move || { exit(c); }) };
    let reaper = { let p = Arc::clone(&p); interleave::spawn("reaper", move || {
        let r = reap(&p);
        interleave::point("reap:done");
        r
    }) };
    let inside = reaper.join().unwrap();
    exiter.join().unwrap();

    schedule.assert_complete();
    assert!(inside.is_none(),
        "an auto-reaped child is never published, so no reaper can ever consume it");
    assert!(!crate::live::zombies::has_zombies(PARENT));
    assert!(c.reaped.load(Ordering::Acquire), "the exit path reaped it itself");
    assert_eq!(p.thread_group.child_acct().snapshot().minflt, 0,
        "an auto-reaped child is never accounted to RUSAGE_CHILDREN");
}

/// Two threads of one process both in `wait4(-1)` when their shared child
/// exits: exactly one gets the status. The zombie is consumed once, so the
/// child accounting that rides on the consuming arm runs once.
///
/// Catches: a consuming reap that leaves the entry queued (the `WNOWAIT` peek
/// semantics used on the consuming path), which reports one exit twice and
/// doubles the child's cost in the parent's `RUSAGE_CHILDREN`.
#[test]
fn two_reapers_released_in_turn_consume_one_zombie_exactly_once() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    crate::live::enqueue_zombie(Arc::clone(&c));
    let schedule = interleave::schedule(&[
        ("first",  "reap:entry"),
        ("first",  "reap:done"),
        ("second", "reap:entry"),
    ]);

    let first = { let p = Arc::clone(&p); interleave::spawn("first", move || {
        let r = reap(&p);
        interleave::point("reap:done");
        r
    }) };
    let second = { let p = Arc::clone(&p); interleave::spawn("second", move || reap(&p)) };
    let results = [first.join().unwrap(), second.join().unwrap()];

    schedule.assert_complete();
    assert_eq!(results.iter().filter(|r| r.is_some()).count(), 1,
        "one exit, one status: never zero and never two");
    let (child, status) = results.into_iter().flatten().next().unwrap();
    assert_eq!((child.vpid, status), (CHILD, STATUS));
    assert!(!crate::live::zombies::has_zombies(PARENT));
    assert_eq!(p.thread_group.child_acct().snapshot().minflt, CHILD_FAULTS,
        "one reap, one accounting pass");
}

