// Linux `acct_collect()` + `acct_process()` from `do_exit`: gather the exiting
// task's accounting facts and append one `acct_v3` record per pid namespace
// that asked for accounting.
//
// Kernel-gated because it reads live task state; the record format, the
// numeric encodings and the admission ladder all live in `fs::acct` and are
// proven hosted.
#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

use ::fs::acct::{AcctFacts, ACORE, AFORK, AGROUP, ASU, AXSIG};
use sched::exit::status;

/// Linux `acct_process()`. `internal_status` is the INTERNAL wait-status
/// encoding (`sched::exit::status`), converted here to the Linux wstatus that
/// `ac_exitcode` carries.
///
/// Returns immediately when no namespace is accounting — the state of every
/// boot that never calls `acct(2)` — so the exit path pays one lock-and-check.
/// # C: O(depth * log N_namespaces)
pub fn acct_process_current(task: &sched::Task, internal_status: i32) {
    if !::fs::acct::accounting_active() { return; }
    let chain = sched::live::pid_namespace_chain(task);
    let facts = collect(task, internal_status);
    ::fs::acct::acct_process(&chain, &facts);
}

/// Linux `acct_collect()`: fold the task's cputime, faults and flags into the
/// record. Called only from the exit path, where `current` IS `task`.
/// # C: O(N_vmas) for the RSS sum
fn collect(task: &sched::Task, internal_status: i32) -> AcctFacts {
    let mut f = AcctFacts::default();

    // `pacct->ac_flag`. AGROUP marks the last task of the thread group, which
    // at this point in do_exit is exactly "the group has no other member".
    let group_dead = task.thread_group.is_single_member();
    if task.forknoexec.load(Ordering::Acquire)  { f.flag |= AFORK; }
    if task.used_superpriv.load(Ordering::Relaxed) { f.flag |= ASU; }
    if status::is_signaled(internal_status)     { f.flag |= AXSIG; }
    if status::core_dumped(internal_status)     { f.flag |= ACORE; }
    if group_dead                               { f.flag |= AGROUP; }

    // `ac->ac_exitcode = pacct->ac_exitcode`, which is `task->exit_code` — the
    // Linux wstatus form, not the raw exit() argument.
    f.exitcode = status::wait_status(internal_status) as u32;

    f.uid = task.creds.ruid.load(Ordering::Acquire);
    f.gid = task.creds.rgid.load(Ordering::Acquire);
    // `task_tgid_nr_ns(current, ns)` / of the real parent: the pid as seen in
    // the namespace the accounting file belongs to.
    let vtgid = task.vtgid.load(Ordering::Acquire);
    f.pid  = if vtgid != 0 { vtgid } else { task.tgid.load(Ordering::Acquire) };
    f.ppid = task.parent_tid.load(Ordering::Acquire);

    // `run_time = ktime_get_ns() - group_leader->start_time`.
    let now = monotonic_ns();
    f.etime_ns = now.saturating_sub(task.start_boottime_ns);
    f.set_btime_from(vfs::inode_times::realtime_now_ns(), f.etime_ns);

    f.utime_ns = task.utime_ns.load(Ordering::Relaxed);
    f.stime_ns = task.stime_ns.load(Ordering::Relaxed);

    // `pacct->ac_mem = vsize / 1024`, summed over the mm's VMAs and recorded
    // only for the last task of the group (Linux `if (group_dead && current->mm)`),
    // SAFETY: mm slot single-mutator per `13§5`; the exiting task runs on this CPU and is the sole reader here.
    if let Some(mm) = unsafe { task.mm_ref() } {
        if group_dead {
            let vsize: u64 = mm.snapshot_vmas().iter()
                .map(|v| v.end.as_u64().saturating_sub(v.start.as_u64())).sum();
            f.mem_kb = vsize / 1024;
        }
    }

    // `ac_io` / `ac_rw`: characters transferred and blocks read-or-written,
    // the same counters `/proc/<pid>/io` reports.
    f.io = task.io_rchar.load(Ordering::Relaxed)
        .saturating_add(task.io_wchar.load(Ordering::Relaxed));
    f.rw = (task.io_read_bytes.load(Ordering::Relaxed)
        .saturating_add(task.io_write_bytes.load(Ordering::Relaxed))) / 512;

    // `acct_collect` (`kernel/acct.c:592-593`) accumulates `current->min_flt`
    // and `current->maj_flt` — the PER-TASK counters, not an mm-wide total.
    // Those counters exist and are charged in the fault handler (F766 added
    // them for `perf_event_open`'s software events); this record simply never
    // read them, so every accounting record reported `ac_majflt` 0 and an
    // `ac_minflt` taken from the wrong scope.
    f.minflt = task.min_flt.load(Ordering::Relaxed);
    f.majflt = task.maj_flt.load(Ordering::Relaxed);
    // `ac_swaps` counts swap-ins charged to the task; Linux has not maintained
    // the underlying counter since 2.6 and always writes 0.
    f.swaps = 0;

    // `ac->ac_tty = tty ? old_encode_dev(tty_devnum(tty)) : 0`.
    // SAFETY: ctty slot single-mutator per `13§5`; the exiting task on this CPU is the sole writer.
    f.tty = task.ctty().as_ref()
        .map(|t| ::fs::acct::record::old_encode_dev(t.rdev()))
        .unwrap_or(0);

    f.set_comm(&task.comm_bytes());
    f
}

#[inline]
fn monotonic_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}
