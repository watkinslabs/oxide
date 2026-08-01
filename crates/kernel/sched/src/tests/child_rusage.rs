// `signal_struct`'s c* counters — what `getrusage(RUSAGE_CHILDREN)` and
// `times(2)`'s `tms_cutime`/`tms_cstime` report — against the real global
// zombie list and the real reap path.
//
// The contract these encode: a child is accounted when it has terminated AND
// been waited for, never merely when it exits. Accounting at exit made an
// unreaped zombie, a `WNOWAIT` peek, and an auto-reaped child (`SIGCHLD`
// ignored / `SA_NOCLDWAIT`, which is never accounted at all) each show up in
// `times(2)` early or wrongly.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use syscall::rusage::Rusage;

use super::common::registry_test_lock;
use crate::signum::Signum;
use crate::task::{SchedClass, Task};

const PARENT: u32 = 700;
const CHILD:  u32 = 701;

fn published(tid: u32) -> Arc<Task> {
    let t = Arc::new(Task::new(tid, "p", SchedClass::Normal { weight: 1024 }));
    t.exit_signal.store(Signum::Sigchld as u8, Ordering::Release);
    t.vtgid.store(tid, Ordering::Release);
    crate::registry::insert(&t);
    t
}

fn fixture() -> (Arc<Task>, Arc<Task>) {
    crate::registry::clear_for_tests();
    let p = published(PARENT);
    let c = published(CHILD);
    c.parent_tid.store(p.tid, Ordering::Release);
    c.set_parent_weak(Some(Arc::downgrade(&p)));
    c.set_pgid(p.pgid());
    (p, c)
}

/// Give `c` a distinctive cost through the SAME entry points the fault, block
/// and context-switch paths use, so a test cannot pass against counters
/// production never writes.
fn charge(c: &Arc<Task>) {
    c.utime_ns.store(700, Ordering::Release);
    c.stime_ns.store(300, Ordering::Release);
    c.thread_group.charge_cpu(true,  700);
    c.thread_group.charge_cpu(false, 300);
    for _ in 0..9 { crate::rusage_charge::fault(c, false); }
    for _ in 0..3 { crate::rusage_charge::fault(c, true); }
    for _ in 0..8 { crate::rusage_charge::ctxsw(c, true); }
    for _ in 0..2 { crate::rusage_charge::ctxsw(c, false); }
    crate::rusage_charge::io_read(c, 2048);
    crate::rusage_charge::io_write(c, 512);
    // What the child had already accumulated from ITS own reaped children.
    c.thread_group.child_acct().accrue(Rusage {
        utime_ns: 70, stime_ns: 30, minflt: 2, majflt: 1, ..Rusage::default()
    });
}

fn reap(p: &Arc<Task>) -> bool {
    crate::live::reap_one(p.tid, p.tgid.load(Ordering::Acquire), -1, p.pgid(), 0).is_some()
}

/// The whole subtree's cost reaches the reaper, not just the immediate child:
/// a shell's `time` over a pipeline depends on it.
#[test]
fn a_reaped_childs_whole_subtree_cost_reaches_the_parents_children_counters() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    charge(&c);

    crate::live::enqueue_zombie(Arc::clone(&c));
    assert!(reap(&p));

    let acct = p.thread_group.child_acct().snapshot();
    assert_eq!(acct.utime_ns, 770, "the grandchildren's time folds in too");
    assert_eq!(acct.stime_ns, 330);
    assert_eq!(acct.minflt, 2 + 9, "faults fold across the subtree, not just time");
    assert_eq!(acct.majflt, 1 + 3);
    assert_eq!(acct.nvcsw, 8);
    assert_eq!(acct.nivcsw, 2);
    assert_eq!(acct.inblock, 4, "512-byte sectors, summed across the subtree");
    assert_eq!(acct.oublock, 1);
    // `times(2)` reads the same two accumulators `getrusage` does, so the two
    // syscalls can never report different child CPU time.
    assert_eq!(p.thread_group.child_acct().cpu_ns(), (acct.utime_ns, acct.stime_ns));
}

/// THE divergence this file exists for. `RUSAGE_CHILDREN` is defined over
/// children that terminated AND were waited for; a zombie nobody has reaped
/// yet contributes nothing.
#[test]
fn an_unreaped_zombie_is_not_yet_visible_in_the_children_counters() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    charge(&c);

    crate::live::enqueue_zombie(Arc::clone(&c));
    assert_eq!(p.thread_group.child_acct().snapshot(), Rusage::default(),
        "exiting is not being waited for");
    assert_eq!(p.thread_group.child_acct().cpu_ns(), (0, 0), "times() agrees");

    assert!(reap(&p));
    assert_eq!(p.thread_group.child_acct().snapshot().utime_ns, 770);
}

/// `waitid(WNOWAIT)` observes the child and leaves it waitable, so it must not
/// account it either — otherwise systemd's peek-then-reap SIGCHLD handler would
/// double-count every service it supervises.
#[test]
fn a_wnowait_peek_neither_accounts_the_child_nor_blocks_the_later_reap() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    charge(&c);
    crate::live::enqueue_zombie(Arc::clone(&c));

    let tgid = p.tgid.load(Ordering::Acquire);
    assert!(crate::live::peek_one(p.tid, tgid, -1, p.pgid(), 0).is_some());
    assert_eq!(p.thread_group.child_acct().snapshot(), Rusage::default(),
        "a peek leaves the child waitable, so it is not yet waited for");

    assert!(reap(&p));
    let acct = p.thread_group.child_acct().snapshot();
    assert_eq!(acct.utime_ns, 770, "and the reap that follows accounts it exactly once");
    assert_eq!(acct.minflt, 11);
}

/// Two reaps of one child are impossible (the second finds nothing), which is
/// what keeps the accumulator from double-counting under a racing sibling.
#[test]
fn a_child_is_accounted_exactly_once_however_many_reaps_are_attempted() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    charge(&c);
    crate::live::enqueue_zombie(Arc::clone(&c));

    assert!(reap(&p));
    assert!(!reap(&p), "nothing left to reap");
    assert_eq!(p.thread_group.child_acct().snapshot().utime_ns, 770);
}

/// `SIGCHLD` set to `SIG_IGN` (POSIX auto-reap): the child is never parked for
/// a `wait4`, so it is never waited for, so it is never accounted. Accounting
/// it at exit gave a supervisor that ignores `SIGCHLD` child CPU time Linux
/// never reports.
#[test]
fn an_autoreaped_child_is_never_accounted() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    charge(&c);
    // Through the real `do_sigaction` core, so the flag sanitiser runs.
    p.sigactions_ref().set_action(
        Signum::Sigchld.as_u8() as usize,
        Some(crate::SaHandler {
            handler: crate::exit::notify::SIG_IGN, flags: 0, restorer: 0, mask: 0,
        }),
    ).expect("SIGCHLD is a settable disposition");

    // The real exit path retires the task first, which is what makes
    // `thread_group_empty(tsk)` true and lets the autoreap arm run at all.
    let _ = c.thread_group.finish_exit(Arc::clone(&c));
    crate::live::enqueue_zombie(Arc::clone(&c));
    assert!(!reap(&p), "an autoreaped child is never published as a zombie");
    assert_eq!(p.thread_group.child_acct().snapshot(), Rusage::default());
    assert_eq!(p.thread_group.child_acct().cpu_ns(), (0, 0));
}

/// The counters live on the thread group (Linux `signal_struct`), so a child
/// reaped by one thread is visible to every sibling — a `time` builtin running
/// on a different thread than the reaper must not read zero.
#[test]
fn a_childs_cost_is_visible_to_every_thread_of_the_reaping_process() {
    let _g = registry_test_lock();
    let (p, c) = fixture();
    let mut sib = Task::new(PARENT + 1, "t", SchedClass::Normal { weight: 1024 });
    sib.join_thread_group(Arc::clone(&p.thread_group));
    sib.tgid.store(p.tid, Ordering::Release);
    let sib = Arc::new(sib);
    crate::registry::insert(&sib);

    c.utime_ns.store(1_234, Ordering::Release);
    c.thread_group.charge_cpu(true, 1_234);
    for _ in 0..7 { crate::rusage_charge::fault(&c, false); }
    crate::live::enqueue_zombie(Arc::clone(&c));
    assert!(reap(&p));

    let from_sib = sib.thread_group.child_acct().snapshot();
    assert_eq!(from_sib.utime_ns, 1_234);
    assert_eq!(from_sib.minflt, 7);
    assert_eq!(from_sib.utime_ns, p.thread_group.child_acct().snapshot().utime_ns);
}

/// `ru_maxrss` is a high-water mark, so the children accumulator takes the MAX
/// of the reaped children rather than summing them — two 100 MiB children in
/// sequence peaked at 100 MiB, not 200.
#[test]
fn the_children_high_water_mark_is_a_max_not_a_sum() {
    let _g = registry_test_lock();
    let (p, _c) = fixture();
    p.thread_group.child_acct().accrue(Rusage { maxrss_kb: 100, minflt: 1, ..Rusage::default() });
    p.thread_group.child_acct().accrue(Rusage { maxrss_kb: 40,  minflt: 1, ..Rusage::default() });
    let acct = p.thread_group.child_acct().snapshot();
    assert_eq!(acct.maxrss_kb, 100);
    assert_eq!(acct.minflt, 2, "every other counter still sums");
}
