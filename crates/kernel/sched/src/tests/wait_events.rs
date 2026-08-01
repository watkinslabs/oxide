// Child stop/continue event selection for the wait(2) family, against the real
// global registry. Encodes the verified contract: a job-control stop needs
// WUNTRACED, a tracer sees its tracee's trap regardless, WNOWAIT leaves the
// event pending, and the wait `rusage` is the child's own counters folded with
// the ones it already accumulated from its own reaped children.

use super::common::registry_test_lock;
use crate::registry::{child_stop_event, WaitChildSnapshot};
use crate::signum::Signum;
use crate::task::{SchedClass, Task};
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use syscall::rusage::Rusage;
use syscall::wait::{WaitEventKind, WCONTINUED, WUNTRACED};

const PARENT: u32 = 400;
const CHILD:  u32 = 401;

fn published(tid: u32) -> Arc<Task> {
    let t = Arc::new(Task::new(tid, "p", SchedClass::Normal { weight: 1024 }));
    t.exit_signal.store(Signum::Sigchld as u8, Ordering::Release);
    // Hosted fixtures carry no VPID by default; stamp it so the snapshot the
    // wait family returns to userspace is checkable.
    t.vtgid.store(tid, Ordering::Release);
    crate::registry::insert(&t);
    t
}

fn child_of(parent: &Arc<Task>, tid: u32) -> Arc<Task> {
    let c = published(tid);
    c.parent_tid.store(parent.tid, Ordering::Release);
    c.set_parent_weak(Some(Arc::downgrade(parent)));
    c.set_pgid(parent.pgid());
    c
}

/// `child_stop_event` for a parent waiting on any child (`pid == -1`).
fn scan(p: &Arc<Task>, want_stop: bool, want_cont: bool, consume: bool)
    -> Option<(WaitChildSnapshot, WaitEventKind, u32)>
{
    let options = if want_stop { WUNTRACED } else { 0 } | if want_cont { WCONTINUED } else { 0 };
    child_stop_event(p.tid, p.tgid.load(Ordering::Acquire), -1, p.pgid(), options, want_stop, want_cont, consume)
}

fn fixture() -> (Arc<Task>, Arc<Task>) {
    crate::registry::clear_for_tests();
    let p = published(PARENT);
    let c = child_of(&p, CHILD);
    (p, c)
}

#[test]
fn a_job_control_stop_is_invisible_to_a_wait_without_wuntraced() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    c.stop_code.store(Signum::Sigtstp as u32, Ordering::Release);
    c.stop_pending.store(true, Ordering::Release);

    assert!(scan(&p, false, false, true).is_none(), "no WUNTRACED, no tracer: nothing to report");
    assert!(c.stop_pending.load(Ordering::Acquire), "a skipped event must stay pending");

    let (child, kind, sig) = scan(&p, true, false, true).expect("WUNTRACED sees the stop");
    assert_eq!(kind, WaitEventKind::Stopped);
    assert_eq!(sig, Signum::Sigtstp as u32);
    assert_eq!(child.vpid, CHILD);
    assert!(!c.stop_pending.load(Ordering::Acquire), "a consumed stop is cleared");
}

#[test]
fn a_tracer_sees_its_tracees_stop_without_wuntraced_and_it_reports_as_a_trap() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    c.traced_by.store(p.tid, Ordering::Release);
    c.stop_code.store(Signum::Sigtrap as u32, Ordering::Release);
    c.stop_pending.store(true, Ordering::Release);

    let (_, kind, sig) = scan(&p, false, false, true).expect("a tracee stop is visible with no options");
    assert_eq!(kind, WaitEventKind::Trapped, "a ptrace stop is CLD_TRAPPED, not CLD_STOPPED");
    assert_eq!(sig, Signum::Sigtrap as u32);
}

#[test]
fn a_stop_reports_as_a_plain_stop_to_a_waiter_that_is_not_the_tracer() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    // Traced by an unrelated task: this waiter is the real parent, so the
    // event is a job-control stop and still needs WUNTRACED.
    c.traced_by.store(PARENT + 50, Ordering::Release);
    c.stop_code.store(Signum::Sigstop as u32, Ordering::Release);
    c.stop_pending.store(true, Ordering::Release);

    assert!(scan(&p, false, false, true).is_none());
    let (_, kind, _) = scan(&p, true, false, true).expect("WUNTRACED sees it");
    assert_eq!(kind, WaitEventKind::Stopped);
}

#[test]
fn wnowait_observes_the_event_without_consuming_it() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    c.stop_code.store(Signum::Sigttin as u32, Ordering::Release);
    c.stop_pending.store(true, Ordering::Release);

    for _ in 0..3 {
        let (_, kind, sig) = scan(&p, true, false, false).expect("peek repeats");
        assert_eq!(kind, WaitEventKind::Stopped);
        assert_eq!(sig, Signum::Sigttin as u32);
        assert!(c.stop_pending.load(Ordering::Acquire));
    }
    assert!(scan(&p, true, false, true).is_some());
    assert!(scan(&p, true, false, true).is_none(), "consumed exactly once");
}

#[test]
fn continued_events_are_reported_only_when_wcontinued_was_requested() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    c.cont_pending.store(true, Ordering::Release);

    assert!(scan(&p, true, false, true).is_none(), "WUNTRACED alone does not report a continue");
    let (_, kind, sig) = scan(&p, false, true, true).expect("WCONTINUED sees it");
    assert_eq!(kind, WaitEventKind::Continued);
    assert_eq!(sig, 0);
    assert!(!c.cont_pending.load(Ordering::Acquire));
}

#[test]
fn a_pending_stop_is_preferred_over_a_pending_continue_on_the_same_child() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    c.stop_code.store(Signum::Sigstop as u32, Ordering::Release);
    c.stop_pending.store(true, Ordering::Release);
    c.cont_pending.store(true, Ordering::Release);

    assert_eq!(scan(&p, true, true, true).unwrap().1, WaitEventKind::Stopped);
    assert_eq!(scan(&p, true, true, true).unwrap().1, WaitEventKind::Continued);
}

#[test]
fn the_wait_rusage_folds_the_childs_own_counters_with_its_accumulated_children() {
    let _g = registry_test_lock();
    let (_p, c) = fixture();
    // Charge through the SAME entry points the fault / block / switch paths
    // use, so the test cannot pass against counters production never writes.
    c.utime_ns.store(2_000_000_000, Ordering::Release);
    c.stime_ns.store(1_000_000_000, Ordering::Release);
    c.thread_group.charge_cpu(true,  2_000_000_000);
    c.thread_group.charge_cpu(false, 1_000_000_000);
    c.thread_group.child_acct().accrue(Rusage {
        utime_ns: 500_000_000, stime_ns: 250_000_000, minflt: 5, majflt: 1,
        inblock: 2, oublock: 3, nvcsw: 4, nivcsw: 6, maxrss_kb: 0,
    });
    for _ in 0..120 { crate::rusage_charge::fault(&c, false); }
    for _ in 0..4   { crate::rusage_charge::fault(&c, true); }
    for _ in 0..31  { crate::rusage_charge::ctxsw(&c, true); }
    for _ in 0..9   { crate::rusage_charge::ctxsw(&c, false); }
    // Block-I/O counters are 512-byte sectors, not byte counts.
    crate::rusage_charge::io_read(&c, 8192);
    crate::rusage_charge::io_write(&c, 1024);

    let s = WaitChildSnapshot::from_task(&c);
    assert_eq!(s.rusage.utime_ns, 2_500_000_000, "own + already-reaped grandchildren");
    assert_eq!(s.rusage.stime_ns, 1_250_000_000);
    // Every counter folds, not just CPU time.
    assert_eq!(s.rusage.minflt, 125);
    assert_eq!(s.rusage.majflt, 5);
    assert_eq!(s.rusage.nvcsw, 35);
    assert_eq!(s.rusage.nivcsw, 15);
    assert_eq!(s.rusage.inblock, 18);
    assert_eq!(s.rusage.oublock, 5);
    // utime_ns/stime_ns on the snapshot stay the child's OWN time — proc-stat
    // style readers must not see the folded value.
    assert_eq!(s.utime_ns, 2_000_000_000);
    assert_eq!(s.stime_ns, 1_000_000_000);
}

#[test]
fn a_stop_belonging_to_another_parent_is_not_reported() {
    let _g = registry_test_lock();
    let (p, _c) = fixture();
    let stranger = published(PARENT + 900);
    stranger.stop_code.store(Signum::Sigstop as u32, Ordering::Release);
    stranger.stop_pending.store(true, Ordering::Release);

    assert!(scan(&p, true, true, true).is_none());
    assert!(stranger.stop_pending.load(Ordering::Acquire));
}

#[test]
fn a_ptrace_event_stop_code_survives_the_registry_and_the_status_encoder() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    c.traced_by.store(p.tid, Ordering::Release);
    let code = syscall::ptrace::event_stop_code(syscall::ptrace::EVENT_EXEC);
    c.stop_code.store(code as u32, Ordering::Release);
    c.stop_pending.store(true, Ordering::Release);

    let (_, kind, got) = scan(&p, false, false, true).expect("a tracee stop is always visible");
    assert_eq!(kind, WaitEventKind::Trapped);
    // The event byte must survive the u8 field this used to be.
    assert_eq!(got as i32, code);
    let wstat = crate::exit::status::stopped_status(got as i32);
    assert_eq!(wstat & 0xff, 0x7f, "WIFSTOPPED");
    assert_eq!((wstat >> 8) & 0xff, syscall::ptrace::SIGTRAP, "WSTOPSIG == SIGTRAP");
    assert_eq!(((wstat >> 16) & 0xff) as u32, syscall::ptrace::EVENT_EXEC);
}

// ---- getrusage `who` aggregation -------------------------------------------
// RUSAGE_SELF is the whole thread group; RUSAGE_THREAD is the calling thread
// alone. Reporting the calling thread for both made a threaded process
// under-report its own cost by whatever its siblings had spent.

/// A second thread of `leader`'s process (Linux `CLONE_THREAD`).
fn sibling_thread(leader: &Arc<Task>, tid: u32) -> Arc<Task> {
    let mut s = Task::new(tid, "t", SchedClass::Normal { weight: 1024 });
    s.join_thread_group(Arc::clone(&leader.thread_group));
    s.tgid.store(leader.tid, Ordering::Release);
    let s = Arc::new(s);
    crate::registry::insert(&s);
    s
}

#[test]
fn rusage_self_sums_every_thread_while_rusage_thread_reports_only_the_caller() {
    let _g = registry_test_lock();
    let (p, _c) = fixture();
    let sib = sibling_thread(&p, PARENT + 11);

    for _ in 0..5 { crate::rusage_charge::fault(&p, false); }
    for _ in 0..2 { crate::rusage_charge::fault(&sib, false); }
    for _ in 0..1 { crate::rusage_charge::fault(&sib, true); }
    crate::rusage_charge::ctxsw(&p, true);
    crate::rusage_charge::ctxsw(&sib, false);
    crate::rusage_charge::io_read(&p, 1024);
    crate::rusage_charge::io_read(&sib, 1024);

    let both_threads = crate::registry::task_rusage_self(&p);
    assert_eq!(both_threads.minflt, 7, "SELF covers the sibling's faults too");
    assert_eq!(both_threads.majflt, 1);
    assert_eq!(both_threads.nvcsw, 1);
    assert_eq!(both_threads.nivcsw, 1);
    assert_eq!(both_threads.inblock, 4, "2048 bytes over both threads, in sectors");

    // Same answer no matter WHICH thread of the process asks.
    assert_eq!(crate::registry::task_rusage_self(&sib), both_threads);

    let caller_only = crate::registry::task_rusage_thread(&p);
    assert_eq!(caller_only.minflt, 5);
    assert_eq!(caller_only.majflt, 0);
    assert_eq!(caller_only.nvcsw, 1);
    assert_eq!(caller_only.nivcsw, 0);
    assert_eq!(caller_only.inblock, 2);
}

#[test]
fn an_exited_threads_cost_still_counts_toward_the_processes_rusage_self() {
    let _g = registry_test_lock();
    let (p, _c) = fixture();
    let sib = sibling_thread(&p, PARENT + 12);
    for _ in 0..9 { crate::rusage_charge::fault(&sib, false); }

    // The thread goes away entirely — the registry holds only a Weak, so
    // dropping the last Arc destroys its per-task counters. Linux keeps the
    // residue on signal_struct; so does the group accumulator.
    drop(sib);

    assert_eq!(crate::registry::task_rusage_self(&p).minflt, 9,
        "a dead thread's faults must not vanish from the process total");
    assert_eq!(crate::registry::task_rusage_thread(&p).minflt, 0,
        "...but they were never the surviving thread's own");
}

#[test]
fn rusage_children_stays_separate_from_the_processes_own_counters() {
    let _g = registry_test_lock();
    let (p, _c) = fixture();
    for _ in 0..3 { crate::rusage_charge::fault(&p, false); }
    p.thread_group.child_acct().accrue(Rusage { minflt: 50, ..Rusage::default() });

    assert_eq!(crate::registry::task_rusage_self(&p).minflt, 3,
        "SELF must not absorb what reaped children cost");
    assert_eq!(p.thread_group.child_acct().snapshot().minflt, 50);
    // RUSAGE_BOTH — what the wait-family out-param reports — is the sum.
    assert_eq!(crate::registry::task_rusage_both(&p).minflt, 53);
}

/// A tracer that is NOT the tracee's parent must be able to `wait` for it.
/// Before the ptrace link joined the candidate matcher, the real-parent filter
/// rejected the tracee outright, so every stop it reported was invisible to the
/// only task that could resume it — `strace -p <unrelated pid>` wedged its
/// target permanently.
#[test]
fn a_tracer_outside_the_parent_chain_sees_its_tracees_stop() {
    let _g = registry_test_lock();
    let (real_parent, c) = fixture();
    let tracer = published(PARENT + 700);
    c.traced_by.store(tracer.tid, Ordering::Release);
    c.stop_code.store(Signum::Sigstop as u32, Ordering::Release);
    c.stop_pending.store(true, Ordering::Release);

    // WNOWAIT-style peek so both waiters can be checked against one event.
    let (_, kind, got) = scan(&tracer, false, false, false)
        .expect("the tracer reaches its tracee through the ptrace link");
    assert_eq!(kind, WaitEventKind::Trapped, "a tracer's wait reports CLD_TRAPPED");
    assert_eq!(got, Signum::Sigstop as u32);

    // The real parent keeps its own view: the two lists are independent, and a
    // job-control stop still needs WUNTRACED there.
    assert!(scan(&real_parent, false, false, false).is_none());
    let (_, kind, _) = scan(&real_parent, true, false, true)
        .expect("the real parent still sees the stop under WUNTRACED");
    assert_eq!(kind, WaitEventKind::Stopped);
}

/// The ptrace list bypasses the clone selector (`eligible_child`'s
/// `if (ptrace || __WALL) return 1;`), so a tracer's plain `waitpid(-1)` sees a
/// tracee whose `exit_signal` is not SIGCHLD — every thread it attached to.
#[test]
fn a_tracer_sees_a_clone_child_without_wclone() {
    let _g = registry_test_lock();
    let (_p, c) = fixture();
    let tracer = published(PARENT + 710);
    c.exit_signal.store(0, Ordering::Release);
    c.traced_by.store(tracer.tid, Ordering::Release);
    c.stop_code.store(Signum::Sigtrap as u32, Ordering::Release);
    c.stop_pending.store(true, Ordering::Release);
    let (_, kind, _) = scan(&tracer, false, false, true)
        .expect("a ptrace wait is not filtered by __WCLONE");
    assert_eq!(kind, WaitEventKind::Trapped);
}

/// A stranger must not reach the tracee through either link.
#[test]
fn an_unrelated_task_still_cannot_wait_for_someone_elses_tracee() {
    let _g = registry_test_lock();
    let (_p, c) = fixture();
    let tracer = published(PARENT + 720);
    let stranger = published(PARENT + 721);
    c.traced_by.store(tracer.tid, Ordering::Release);
    c.stop_code.store(Signum::Sigstop as u32, Ordering::Release);
    c.stop_pending.store(true, Ordering::Release);
    assert!(scan(&stranger, true, true, true).is_none());
}

/// Zero is not a stop code. A tracer that resumed its tracee without waiting
/// wrote its `data` into the same cell and the tracee then cleared it; Linux's
/// `wait_task_stopped` bails on zero before consuming the event rather than
/// reporting `WIFSTOPPED` with signal 0.
#[test]
fn a_cleared_stop_code_is_not_reported_and_does_not_consume_the_event() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    c.stop_code.store(0, Ordering::Release);
    c.stop_pending.store(true, Ordering::Release);
    assert!(scan(&p, true, false, true).is_none());
    // The flag survives, so the real stop that follows is still reportable.
    assert!(c.stop_pending.load(Ordering::Acquire));
    c.stop_code.store(Signum::Sigtstp as u32, Ordering::Release);
    let (_, _, got) = scan(&p, true, false, true).expect("the next real stop reports");
    assert_eq!(got, Signum::Sigtstp as u32);
}
