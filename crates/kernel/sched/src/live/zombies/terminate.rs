// Fatal-signal termination of the running task (Linux `get_signal`'s
// `do_group_exit(signo)` reached from an unresolvable fault rather than from
// the syscall-return tail). Split out of `zombies.rs` per `08§7`.

use core::sync::atomic::Ordering;

use crate::Task;

/// Terminate the CURRENT task as if killed by signal `sig` (default fatal
/// action) and schedule away — DIVERGES. The page-fault handler calls this
/// when a USER-mode fault is unresolvable: Linux delivers SIGSEGV/SIGBUS whose
/// default action terminates the faulting process; the kernel must kill that
/// ONE task, never halt the machine. Mirrors `sys_exit`'s teardown so the
/// parent reaps it (wait status = `sig | 0x100`, "killed by signal") and the
/// system keeps running past a single service's bad-pointer crash.
/// # SAFETY: caller is the exception handler running on the faulting task's
/// kernel stack, IRQs off, runqueue installed.
/// # C: O(N_tasks) reparent + O(log N) schedule
pub fn terminate_current_with_signal(sig: u8) -> ! {
    // Linux fatal default actions are group-fatal (`get_signal` ->
    // `do_group_exit(signo)`): latch the group exit code FIRST so every
    // sibling — and the leader, which dies from the SIGKILL posted below —
    // reports THIS signal rather than SIGKILL, then zap.
    let requested = crate::signum::killed_status(sig as u32);
    let status = match crate::live::current() {
        Some(current) => {
            crate::timers::clear_process_timers(current);
            let decision = current.thread_group.group_exit(requested);
            if decision.zap { crate::live::zap_other_threads(); }
            decision.status
        }
        None => { crate::live::zap_other_threads(); requested }
    };
    if let Some(rq) = crate::live::global() {
        let raw = rq.current.load(Ordering::Acquire);
        if !raw.is_null() {
            // SAFETY: rq.current installed via Arc::into_raw, non-null; we run
            // ON this task so no concurrent freer; reads/atomic-stores only.
            let task: &Task = unsafe { &*raw };
            task.thread_group.latch_final_exit(status);
            task.exit_status.store(status, Ordering::Release);
            crate::live::vfork_done(task); // clear + wake a parked vfork parent (signal-death)
            crate::cgroup::exit_task(task);
            // Robust-futex recovery (Linux do_exit -> exit_robust_list): a
            // thread killed by a fatal signal while holding a robust mutex must
            // mark it FUTEX_OWNER_DIED and wake a waiter, else a peer blocked on
            // that lock hangs forever. MUST run before replace_mm below (the
            // walk reads the dying task's still-mapped user list). Routed via
            // the sched hook because the walk body lives in `ipc`.
            let rl = task.robust_list_head.load(Ordering::Acquire);
            if rl != 0 {
                let vt = task.vtid.load(Ordering::Acquire);
                let owner_tid = if vt != 0 { vt } else { task.tid };
                crate::live::run_robust_exit(rl, owner_tid);
            }
            // PI-futex ownership handoff (Linux do_exit -> exit_pi_state_list).
            // Runs for EVERY dying thread, robust list or not: the kernel's own
            // PI ownership records are what release a PTHREAD_PRIO_INHERIT
            // mutex to the next waiter with FUTEX_OWNER_DIED. Same mm-still-
            // mapped requirement as the robust walk above.
            {
                let vt = task.vtid.load(Ordering::Acquire);
                crate::live::run_pi_exit(if vt != 0 { vt } else { task.tid });
            }
            // SysV SEM_UNDO recovery (Linux do_exit -> exit_sem). Unconditional
            // here: the group-exit latch above has already made this a
            // group-fatal death, so the whole thread group — the unit the undo
            // list is keyed on — is going away.
            let vtg = task.vtgid.load(Ordering::Acquire);
            let tg = task.tgid.load(Ordering::Acquire);
            crate::live::run_sysvsem_exit(if vtg != 0 { vtg } else { tg });
            // Final `put_cred` for the keyring state (Linux `exit_creds`). A
            // task killed by a fatal signal strands exactly the same thread
            // keyring, assumed authority and session reference as one that
            // called `exit(2)`, and a recycled tid would then inherit them.
            // Runs before `mark_done` so the group-dead test still counts this
            // thread live.
            crate::live::run_keyring_exit(task);
            // SAFETY: exiting task on this CPU; sole writer per single-mutator.
            unsafe { task.replace_fd_table(None); task.replace_mm(None); }
            // Linux `do_exit`: `if (group_dead) disassociate_ctty(1)`. A
            // session leader killed by a fatal signal owes its session the
            // same hangup as one that called `exit(2)` — the SIGSEGV of a
            // login shell must still SIGHUP its foreground job and revoke the
            // line, or the next session inherits a live handle on it.
            crate::live::run_disassociate_ctty(task);
            super::reparent_children(task.tid);
            crate::live::mark_done(task);
            // A non-leader thread is auto-released in the switch tail. The
            // group leader publishes the process exit and SIGCHLD once the
            // group-fatal signal reaches it.
            if task.tid == task.tgid.load(Ordering::Acquire) {
                super::signal_child_exit(task);
            }
        }
    }
    // SAFETY: exception ctx; preempt-off; Zombie state means no re-enqueue.
    unsafe { crate::live::schedule(); }
    loop { core::hint::spin_loop(); }
}
