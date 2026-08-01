// The exit half of BSD process accounting: gather the exiting PROCESS's
// accounting facts and append one `acct_v3` record to every pid namespace that
// asked for accounting.
//
// One record per PROCESS, not per thread: the record is written when the last
// task of the thread group goes, and its cputime and fault counts are the
// whole group's — a thread exiting adds nothing to the log by itself.
//
// Kernel-gated because it reads live task state; the record format, the
// numeric encodings, the free-space hysteresis and the admission ladder all
// live in `fs::acct` and are proven hosted. The namespace-relative pid
// resolution is `acct_ns.rs`, which is ungated for the same reason.
#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

use ::fs::acct::{AcctFacts, ACORE, AFORK, AGROUP, ASU, AXSIG};
use sched::exit::status;

/// Append this exiting task's accounting record, if it is the last of its
/// thread group and any namespace is accounting. `internal_status` is the
/// INTERNAL wait-status encoding (`sched::exit::status`), converted here to the
/// Linux wstatus that `ac_exitcode` carries.
///
/// Returns immediately when no namespace is accounting — the state of every
/// boot that never calls `acct(2)` — so the exit path pays one lock-and-check.
/// # C: O(depth * log N_namespaces)
pub fn acct_process_current(task: &sched::Task, internal_status: i32) {
    if !::fs::acct::accounting_active() { return; }
    // The record describes a PROCESS. A non-final thread's exit contributes to
    // the group counters (charged at the event, not here) and writes nothing.
    if !task.thread_group.is_single_member() { return; }
    let now = monotonic_ns();
    let facts = collect(task, internal_status, now);
    let targets = ns_targets(task);
    ::fs::acct::acct_process(&targets, &facts, now);
    // A pid namespace dies with its init, and its accounting file dies with
    // it: the record above is the namespace's last, and leaving the file bound
    // would keep a dead namespace's reference on the accounting filesystem.
    let own_ns = targets.first().map(|t| t.ns_id).unwrap_or(crate::acct_ns::INITIAL_PID_NS);
    let is_ns_init = task.vtgid.load(Ordering::Acquire) == NS_INIT_VPID;
    if own_ns != crate::acct_ns::INITIAL_PID_NS && is_ns_init {
        ::fs::acct::acct_exit_ns(own_ns);
    }
}

/// The visible thread-group id every pid namespace's init carries.
const NS_INIT_VPID: u32 = 1;

/// One target per pid namespace in the exiting task's ancestor chain, each
/// carrying the numbers THAT namespace gives the process and its real parent.
/// # C: O(depth log N_tasks)
fn ns_targets(task: &sched::Task) -> alloc::vec::Vec<::fs::acct::NsTarget> {
    let parent = sched::registry::lookup(task.parent_tid.load(Ordering::Acquire));
    let views: alloc::vec::Vec<crate::acct_ns::NsView> = task.pid.namespaces().iter()
        .map(|owner| {
            let namespace = owner.get_active();
            let (pid, ppid) = match &namespace {
                Some(active) => (
                    task.pid_nr_ns(active),
                    parent.as_ref().and_then(|p| {
                        sched::registry::tgid_nr_in(p, active)
                    }).unwrap_or(0),
                ),
                None => (0, 0),
            };
            crate::acct_ns::NsView { ns_id: owner.id().as_u64(), pid, ppid }
        })
        .collect();
    crate::acct_ns::targets(&views)
}

/// Fold the process's cputime, faults and flags into the record.
/// # C: O(N_vmas) for the address-space size sum
fn collect(task: &sched::Task, internal_status: i32, now_ns: u64) -> AcctFacts {
    let mut f = AcctFacts::default();

    // AGROUP marks the last task of the thread group, which is the only task
    // that gets here.
    if task.forknoexec.load(Ordering::Acquire)     { f.flag |= AFORK; }
    if task.used_superpriv.load(Ordering::Relaxed) { f.flag |= ASU; }
    if status::is_signaled(internal_status)        { f.flag |= AXSIG; }
    if status::core_dumped(internal_status)        { f.flag |= ACORE; }
    f.flag |= AGROUP;

    // `ac_exitcode` is the Linux wstatus form, not the raw exit() argument.
    f.exitcode = status::wait_status(internal_status) as u32;

    f.uid = task.creds.ruid.load(Ordering::Acquire);
    f.gid = task.creds.rgid.load(Ordering::Acquire);
    // `ac_pid` / `ac_ppid` are filled per target namespace by the writer.

    // Elapsed wall-clock life of the thread group.
    f.etime_ns = now_ns.saturating_sub(task.start_boottime_ns);
    f.set_btime_from(vfs::inode_times::realtime_now_ns(), f.etime_ns);

    // WHOLE-PROCESS cputime and faults: every thread's charge accumulates into
    // the group counters at the event, so these already cover the threads that
    // exited earlier and left no record of their own.
    let (utime, stime) = task.thread_group.cpu_sample();
    f.utime_ns = utime;
    f.stime_ns = stime;
    let g = task.thread_group.group_acct().snapshot();
    f.minflt = g.minflt;
    f.majflt = g.majflt;

    // `ac_mem` is the address space's total size in KiB, recorded only for the
    // last task of the group — which is this one.
    // SAFETY: mm slot single-mutator per `13§5`; the exiting task runs on this CPU and is the sole reader here.
    if let Some(mm) = unsafe { task.mm_ref() } {
        let vsize: u64 = mm.snapshot_vmas().iter()
            .map(|v| v.end.as_u64().saturating_sub(v.start.as_u64())).sum();
        f.mem_kb = vsize / 1024;
    }

    // `ac_io`, `ac_rw` and `ac_swaps` are BSD-era fields the record still
    // reserves but no longer maintains: every record carries zero in all
    // three, and `sa`/`lastcomm` report them as such. Filling them with this
    // kernel's real byte counters would make an identical workload produce
    // different numbers here than on the system these tools were written for,
    // which is the one thing an accounting log must not do.
    f.io = 0;
    f.rw = 0;
    f.swaps = 0;

    // SAFETY: ctty slot single-mutator per `13§5`; the exiting task on this CPU is the sole writer.
    f.tty = task.ctty().as_ref()
        .map(|t| ::fs::acct::record::old_encode_dev(t.rdev()))
        .unwrap_or(0);

    f.set_comm(&task.comm_bytes());
    f
}

/// Monotonic nanoseconds, the clock both the elapsed-time field and the
/// free-space check interval are denominated in. # C: O(1)
#[inline]
pub fn monotonic_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}
