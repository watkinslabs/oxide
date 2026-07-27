// Fork/clone inheritance — Linux `copy_process` / `dup_task_struct`.
//
// Single owner for BOTH arches. The two per-arch `spawn_user_thread_for_fork`
// bodies each carried their own copy of this block, and they had already
// drifted: the aarch64 copy was missing `ioprio` and `exe_path`, so an
// `ioprio_set(2)` value and `/proc/<pid>/exe` survived fork on x86_64 and
// silently did not on aarch64. One function, one place to add to.

use core::sync::atomic::Ordering;

use crate::Task;

/// Copy every piece of per-task state Linux's `copy_process` inherits from the
/// forking parent. No-op on the boot path, where `current()` is None and the
/// task keeps its `Task::new_user` defaults (`Creds::root()` included).
///
/// # SAFETY: `task` is local to the spawn path and not yet scheduled, so this
/// is the sole writer; `parent` is the running task on this CPU, whose fields
/// are single-mutator per `13§5`.
/// # C: O(N_seccomp_filters + N_landlock_rules)
pub(super) fn inherit_from_parent(task: &mut Task) {
    let Some(parent) = crate::live::current() else { return };
    // SAFETY: parent is the running task on this CPU (single-mutator
    // invariant per `13§5`); `task` is local and not yet scheduled.
    unsafe { task.creds = parent.creds.snapshot(); }
    // oom_score_adj is inherited across fork and CLONE_THREAD exactly as
    // Linux copies it in dup_task_struct.
    task.oom_score_adj.store(parent.oom_score_adj(), Ordering::Release);
    // PR_SET_TIMERSLACK state is inherited across fork and preserved by
    // exec, like Linux task_struct::timer_slack_ns.
    task.timer_slack_ns.store(parent.timer_slack_ns.load(Ordering::Acquire), Ordering::Release);
    // Linux sched_fork(): policy, RT priority, nice and load weight are
    // inherited across fork/clone; SCHED_RESET_ON_FORK demotes the child.
    crate::live::sched_fork::inherit_sched_params(&task, &parent);
    // ioprio_set/get(2): I/O priority is inherited across fork.
    task.ioprio.store(parent.ioprio.load(Ordering::Acquire), Ordering::Release);
    // /proc/<pid>/exe is inherited across fork until the child execs (Linux
    // dup_mm carries exe_file). Also lets the wedge / [EXIT] dumps name a
    // pre-exec fork-child by the program that forked it.
    task.set_exe_path(parent.exe_path());
    // comm is inherited across fork/CLONE_THREAD exactly like Linux
    // copies task_struct::comm in dup_task_struct — a pthread_create'd
    // thread starts with the creator's name until it renames itself via
    // prctl(PR_SET_NAME)/pthread_setname_np.
    task.set_comm_bytes(parent.comm_bytes());
    // SUID_DUMP_* / THP_DISABLE are inherited across fork/clone (Linux
    // copies mm->flags).
    task.dumpable.store(parent.dumpable.load(Ordering::Acquire), Ordering::Release);
    task.thp_disable.store(parent.thp_disable.load(Ordering::Acquire), Ordering::Release);
    // PR_SET_TIMERSLACK's restore-target rides along with the live value
    // (Linux copies `default_timer_slack_ns` in `dup_task_struct`).
    task.default_timer_slack_ns
        .store(parent.default_timer_slack_ns.load(Ordering::Acquire), Ordering::Release);
    // PR_MCE_KILL policy lives in `task_struct::flags`, copied by fork.
    task.mce_kill.store(parent.mce_kill.load(Ordering::Acquire), Ordering::Release);
    // PR_SET_NO_NEW_PRIVS is INHERITED across fork/clone and never cleared
    // (Linux `dup_task_struct` copies the PFA bit; `copy_seccomp` re-asserts
    // it). Without this a no-new-privs sandbox could fork and the child
    // would run WITHOUT the restriction — it could then exec a setuid
    // binary or gain file capabilities, which is the whole thing the flag
    // exists to prevent.
    if parent.no_new_privs.load(Ordering::Acquire) {
        task.no_new_privs.store(true, Ordering::Release);
    }
    // Namespace publication runs after this allocation. Seed a visible PID;
    // clone namespace work replaces it with 1 when the child becomes a
    // new PID namespace's init task.
    static NEXT_VPID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(2);
    let v = NEXT_VPID.fetch_add(1, Ordering::AcqRel);
    task.vtgid.store(v, Ordering::Release);
    task.vtid.store(v, Ordering::Release);
    // Seccomp is INHERITED across fork/clone and PRESERVED across execve
    // (Linux copies the filter chain in dup_task_struct; execve never
    // clears it). Without this a seccomp-sandboxed process could fork() and
    // the child would run with an EMPTY filter set — a trivial sandbox
    // escape (`fork(); <forbidden syscall in child>`).
    // SAFETY: parent is the running task on this CPU (single-mutator read
    // per `13§5`); `task` is local and not yet scheduled (single-mutator
    // write). The child gets its own copy of the filter chain.
    unsafe { *task.seccomp_filters.get() = (*parent.seccomp_filters.get()).clone(); }
    // Landlock ruleset chain is likewise inherited across fork and kept
    // across execve — a Landlock-confined process's children stay confined.
    let parent_chain = parent.landlock_chain.lock().clone();
    *task.landlock_chain.lock() = parent_chain;
}
