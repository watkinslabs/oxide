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
    // Linux `copy_process` → `mpol_dup(p->mempolicy)`:
    // the thread's NUMA policy is inherited by fork AND by CLONE_THREAD.
    for i in 0..task.mempolicy.len() {
        task.mempolicy[i].store(parent.mempolicy[i].load(Ordering::Acquire), Ordering::Release);
    }
    // I/O priority is inherited across fork. This is the UNSHARED copy;
    // `CLONE_IO` replaces it with the parent's own context afterwards, since
    // the clone flags do not reach the spawn path.
    task.set_io_context(crate::ioprio::copy_io(&parent.io_context(), false));
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
    // `prctl(PR_SET_TSC)` and `prctl(PR_SET_TAGGED_ADDR_CTRL)` are thread
    // flags, which fork copies wholesale with the rest of `thread_info`. A
    // child that did NOT inherit the TSC trap would be a one-`fork()` escape
    // from the very restriction its parent asked for.
    task.tsc_sigsegv.store(parent.tsc_sigsegv.load(Ordering::Acquire), Ordering::Release);
    task.tagged_addr.store(parent.tagged_addr.load(Ordering::Acquire), Ordering::Release);
    // PR_MCE_KILL policy lives in `task_struct::flags`, copied by fork.
    task.mce_kill.store(parent.mce_kill.load(Ordering::Acquire), Ordering::Release);
    // PR_SET_IO_FLUSHER is `PF_MEMALLOC_NOIO | PF_LOCAL_THROTTLE`, also in
    // `task_struct::flags`: `copy_process` clears only PF_SUPERPRIV/WQ_WORKER/
    // IDLE/NO_SETAFFINITY, so a forked helper of a block server inherits the
    // no-IO-reclaim promise its parent made.
    task.io_flusher.set(parent.io_flusher.get());
    // `PR_SET_SYSCALL_USER_DISPATCH` is NOT inherited: `copy_process` runs
    // `clear_syscall_work_syscall_user_dispatch(tsk)`, so a fork child starts
    // with dispatch off (a fresh `Task` already does).
    // PR_SET_NO_NEW_PRIVS is INHERITED across fork/clone and never cleared
    // (Linux `dup_task_struct` copies the PFA bit; `copy_seccomp` re-asserts
    // it). Without this a no-new-privs sandbox could fork and the child
    // would run WITHOUT the restriction — it could then exec a setuid
    // binary or gain file capabilities, which is the whole thing the flag
    // exists to prevent.
    if parent.no_new_privs.load(Ordering::Acquire) {
        task.no_new_privs.store(true, Ordering::Release);
    }
    // `arch_prctl` per-thread arch state. Linux carries all of it in
    // `thread_info::flags` and `thread_struct`, both of which `dup_task_struct`
    // copies wholesale, so a fork child inherits them and only `execve` clears
    // them. TIF_NOCPUID: a child of a thread that disabled `cpuid` must also
    // see `cpuid` fault, or a determinism sandbox leaks through fork. The CET
    // feature/lock pair: a child of a shadow-stack thread must not be able to
    // re-open a facility its parent locked.
    task.nocpuid.store(parent.nocpuid.load(Ordering::Acquire), Ordering::Release);
    inherit_fpu_state(task, parent);
    // POR_EL0 is separate from the aarch64 FPSIMD image, so it is inherited
    // explicitly. x86 PKRU rides in the xstate copy above.
    #[cfg(target_arch = "aarch64")]
    task.pkey_rights.store(parent.pkey_rights.load(Ordering::Acquire), Ordering::Release);
    task.shstk_features.store(parent.shstk_features.load(Ordering::Acquire), Ordering::Release);
    task.shstk_locked.store(parent.shstk_locked.load(Ordering::Acquire), Ordering::Release);
    // The child's visible numbers are NOT seeded here: they are drawn from the
    // PID namespace it ends up in, which clone only publishes afterwards.
    // Seccomp is INHERITED across fork/clone and PRESERVED across execve
    // (Linux `copy_seccomp` in `copy_process`; execve never clears it).
    // Without this a seccomp-sandboxed process could fork() and the child
    // would run with an EMPTY filter set — a trivial sandbox escape
    // (`fork(); <forbidden syscall in child>`).
    //
    // The MODE rides with the chain. `copy_seccomp` copies `p->seccomp =
    // current->seccomp` wholesale, mode included; copying only the chain
    // left the child at `SECCOMP_MODE_DISABLED`, where `__secure_computing`
    // returns before it ever looks at the inherited filters — the same
    // escape by another route — and `PR_GET_SECCOMP` / `/proc/<pid>/status`
    // reported the child unconfined. A `SECCOMP_MODE_DEAD` parent cannot
    // fork (it is being killed), so the value is copied verbatim.
    let parent_chain = parent.seccomp_filters.lock().clone();
    *task.seccomp_filters.lock() = parent_chain;
    task.seccomp_mode.store(parent.seccomp_mode.load(Ordering::Acquire), Ordering::Release);
    // Landlock ruleset chain is likewise inherited across fork and kept
    // across execve — a Landlock-confined process's children stay confined.
    let parent_domain = parent.landlock_domain.lock().clone();
    *task.landlock_domain.lock() = parent_domain;
}

/// Snapshot the running parent's architectural state, then give the child an
/// exact private copy. Fork runs preempt-off, so neither buffer can change
/// between the snapshot and copy. # C: O(ARCH_FPU_SIZE)
fn inherit_fpu_state(task: &Task, parent: &Task) {
    // SAFETY: parent is current and fork's caller holds preemption off; task
    // is unpublished. Both buffers are distinct `ARCH_FPU_SIZE` allocations.
    unsafe {
        let src = (*parent.fpu_state.get()).as_mut_ptr();
        let dst = (*task.fpu_state.get()).as_mut_ptr();
        #[cfg(target_arch = "x86_64")]
        hal_x86_64::fpu_save(src as *mut hal_x86_64::FpuStateX86_64);
        #[cfg(target_arch = "aarch64")]
        hal_aarch64::fpu_save(src as *mut hal_aarch64::FpuStateAArch64);
        core::ptr::copy_nonoverlapping(src, dst, crate::ARCH_FPU_SIZE);
    }
}
