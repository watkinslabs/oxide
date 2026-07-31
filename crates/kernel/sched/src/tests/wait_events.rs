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
    c.utime_ns.store(2_000_000_000, Ordering::Release);
    c.stime_ns.store(1_000_000_000, Ordering::Release);
    c.thread_group.child_acct().accrue(Rusage {
        utime_ns: 500_000_000, stime_ns: 250_000_000, minflt: 5, majflt: 1,
        inblock: 2, oublock: 3, nvcsw: 4, nivcsw: 6, maxrss_kb: 0,
    });
    c.min_flt.store(120, Ordering::Relaxed);
    c.maj_flt.store(4, Ordering::Relaxed);
    c.nvcsw.store(31, Ordering::Relaxed);
    c.nivcsw.store(9, Ordering::Relaxed);
    // Block-I/O counters are 512-byte sectors, not byte counts.
    c.io_read_bytes.store(8192, Ordering::Relaxed);
    c.io_write_bytes.store(1024, Ordering::Relaxed);

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
fn a_dying_childs_whole_subtree_cpu_time_reaches_the_parents_children_counters() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    c.utime_ns.store(700, Ordering::Release);
    c.stime_ns.store(300, Ordering::Release);
    c.min_flt.store(9, Ordering::Relaxed);
    c.maj_flt.store(3, Ordering::Relaxed);
    c.nvcsw.store(8, Ordering::Relaxed);
    c.nivcsw.store(2, Ordering::Relaxed);
    c.io_read_bytes.store(2048, Ordering::Relaxed);
    c.io_write_bytes.store(512, Ordering::Relaxed);
    // What the child had already accumulated from ITS own exited children.
    c.thread_group.child_acct().accrue(Rusage {
        utime_ns: 70, stime_ns: 30, minflt: 2, majflt: 1, ..Rusage::default()
    });

    crate::live::enqueue_zombie(Arc::clone(&c));

    let acct = p.thread_group.child_acct().snapshot();
    assert_eq!(acct.utime_ns, 770,
        "getrusage(RUSAGE_CHILDREN)/times() must see the grandchildren's time too");
    assert_eq!(acct.stime_ns, 330);
    assert_eq!(acct.minflt, 2 + 9, "faults fold across the subtree, not just time");
    assert_eq!(acct.majflt, 1 + 3);
    assert_eq!(acct.nvcsw, 8);
    assert_eq!(acct.nivcsw, 2);
    assert_eq!(acct.inblock, 4, "512-byte sectors, summed across the subtree");
    assert_eq!(acct.oublock, 1);
    // Leave the global zombie list as it was found.
    assert!(crate::live::reap_one(p.tid, p.tgid.load(Ordering::Acquire), -1, p.pgid(), 0).is_some());
}

#[test]
fn a_childs_cost_is_visible_to_every_thread_of_the_reaping_process() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    // A second thread of the SAME process (Linux CLONE_THREAD).
    let mut sib = Task::new(PARENT + 1, "t", SchedClass::Normal { weight: 1024 });
    sib.join_thread_group(Arc::clone(&p.thread_group));
    sib.tgid.store(p.tid, Ordering::Release);
    let sib = Arc::new(sib);
    crate::registry::insert(&sib);

    c.utime_ns.store(1_234, Ordering::Release);
    c.min_flt.store(7, Ordering::Relaxed);
    crate::live::enqueue_zombie(Arc::clone(&c));

    // getrusage(RUSAGE_CHILDREN) from the sibling must see it: the counters
    // are process-wide (Linux signal_struct), not per-thread.
    let from_sib = sib.thread_group.child_acct().snapshot();
    assert_eq!(from_sib.utime_ns, 1_234);
    assert_eq!(from_sib.minflt, 7);
    assert_eq!(from_sib.utime_ns, p.thread_group.child_acct().snapshot().utime_ns);

    assert!(crate::live::reap_one(p.tid, p.tgid.load(Ordering::Acquire), -1, p.pgid(), 0).is_some());
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
