// 060 exit — one syscall, one file (docs/53 §0). Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_exit_group(2)` (slot 231): terminate the ENTIRE thread-group, not just
/// the caller. Linux `do_group_exit` → `zap_other_threads` SIGKILLs every
/// sibling, then the caller exits. `sys_exit` (slot 60) keeps single-thread
/// semantics for `pthread_exit`. Routing both to plain `sys_exit` (the prior
/// bug) left a multi-threaded process's siblings alive after `exit_group` and,
/// worse, after a fatal signal — leaking any libc lock the dying thread held.
/// # SAFETY: dispatch ctx on task's syscall kstack, IRQs masked.
/// # C: O(N_threads) + O(log N)
pub fn sys_exit_group(args: &SyscallArgs) -> i64 {
    if let Some(current) = sched::live::current() {
        sched::timers::clear_process_timers(current);
    }
    sched::live::zap_other_threads();
    sys_exit(args)
}

/// sys_exit: mark Zombie, stash exit_status, schedule away.
/// # SAFETY: dispatch ctx on task's syscall kstack, IRQs masked.
/// # C: O(log N) + O(1)
pub fn sys_exit(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let _ = args;
    // No runqueue (arm direct drop_to_el0 pre-P2-13e): nothing
    // to Zombie. Pre-P2-22 fallthrough behavior.
    if sched::live::global().is_none() {
        return 0;
    }
    if let Some(rq) = sched::live::global() {
        // Mark prev Zombie + post SIGCHLD without bumping the
        // rq.current strong count. `schedule()` below detects
        // the Zombie state on prev and transfers the swap_current-
        // returned Arc into ZOMBIES — that avoids the prior leak
        // where the bumped Arc was permanently stranded on the
        // dead task's kernel-stack frame inside `schedule()`.
        let raw = rq.current.load(Ordering::Acquire);
        if !raw.is_null() {
            // SAFETY: rq.current was installed via Arc::into_raw and is non-null after install_global; the AtomicPtr's strong-ref-via-raw keeps the pointee alive across this borrow; we are running ON this task so no concurrent freer.
            let task: &sched::Task = unsafe { &*raw };
            task.debug_check_canary("sys_exit_current");
            if task.thread_group.is_single_member() {
                sched::timers::clear_process_timers(task);
            }
            // DIAG (debug-watchdog): a non-zero exit dumps the task's recent
            // syscalls so a service's status=1/FAILURE shows its failing call.
            sched::diag::dump_exit_recent(task.name, args.a0);
            #[cfg(feature = "debug-brokerdump")]
            if args.a0 != 0 {
                // SAFETY: current task is the sole exe_path mutator while executing exit_group.
                let broker = unsafe { (*task.exe_path.get()).as_ref().is_some_and(|p| p.contains("dbus-broker")) };
                if broker {
                    // SAFETY: exiting current task owns its fd-table slot until replace_fd_table below.
                    if let Some(fdt) = unsafe { task.fd_table_ref() } {
                        vfs::fdtable::debug::dump(fdt);
                    }
                }
            }
            // DIAG (debug-cgroup): a non-zero exit dumps the task's cgroup v2
            // path. logind's GetSessionByPID / sd_pid_get_session resolve a pid's
            // session from its `session-cN.scope` cgroup element; if a greeter
            // payload (gnome-shell) exits non-zero with a `user@NNN.service`
            // cgroup instead of `session-cN.scope`, it escaped its session scope
            // → NoSessionForPID → "Failed to find any matching session".
            #[cfg(feature = "debug-cgroup")]
            if args.a0 != 0 {
                klog::write_raw(b"[EXITCG tid=");
                klog::write_dec_u64(task.tid as u64);
                klog::write_raw(b" ");
                klog::write_raw(task.name.as_bytes());
                klog::write_raw(b"] ");
                let cg = cgroup::proc_cgroup(task.tid as u64);
                klog::write_raw(cg.as_bytes());
            }
            // DIAG (debug-atexit): exit(127) = ld.so died on garbage mapped
            // content — verify every non-writable file-backed page against
            // the page cache while the mapping is still live ([MAPDIFF]).
            #[cfg(all(target_arch = "x86_64", feature = "debug-atexit"))]
            if args.a0 == 127 { pmm::user_as::diag_verify_file_pages(); }
            task.exit_status.store(args.a0 as i32, Ordering::Release);
            sched::live::vfork_done(task); // F156 vfork: clear + wake parent
            // cgroup v2 (`26§4`): drop the exiting task from its
            // cgroup so cgroup.procs / cgroup.events `populated`
            // reflect reality — systemd keys service liveness on it.
            cgroup::on_exit(task.tid as u64);
            // F205: drop the exiting task's fd_table Arc reference
            // BEFORE waking the parent. Linux closes a process's
            // open files at exit (do_exit → exit_files → put_files_struct);
            // without this, every File in the table stays alive until
            // the parent reaps via wait4. That breaks pipe POLL_HUP
            // propagation — the shell child's stdout-pipe-write-end
            // File doesn't drop, pipe_close_hook doesn't fire,
            // writers stays > 0, dropbear's select on the read end
            // never reports POLL_HUP, and CHANNEL_EOF never goes
            // out. The bug was load-bearing on aarch64 because
            // dropbear-aarch64 keeps SIGCHLD masked across pselect
            // (musl maps select(2) → pselect6 with sigmask=NULL),
            // so the SIGCHLD-handler-driven reap path that papers
            // over the leak on x86 can't run on arm. Dropping here
            // makes the close-on-exit semantic uniform across the
            // signal-delivery vs poll-driven wake paths.
            debug_ssh! {
                klog::write_raw(b"[INFO]  ssh-trace: sys_exit tid=");
                klog::write_dec_u64(task.tid as u64);
                klog::write_raw(b" drop_fd_table\n");
            }
            // F242: CLONE_CHILD_CLEARTID — Linux do_exit clears the
            // user-pointed-to tid + FUTEX_WAKEs anyone parked there.
            // pthread_join uses this exact mechanism; without it,
            // joining threads hang forever.
            let ctid = task.clear_child_tid.load(Ordering::Acquire);
            // Best-effort, like Linux do_exit's `put_user(0, tidptr)`: the write
            // must NOT fault the kernel if the page is unmapped. A range check
            // (< USER_VA_END) is insufficient — a threaded runtime (Go/musl)
            // can free a thread's stack/TLS before exit, leaving clear_child_tid
            // pointing at an UNMAPPED page → a raw write there #PF'd the kernel
            // (crashed every threaded app on exit). Validate the writable VMA
            // first; skip silently if gone (Linux's put_user fault is ignored).
            if ctid != 0 && crate::userbuf::validate_user_buf_writable(ctid, 4, 4).is_ok() {
                // SAFETY: validated as a mapped, writable 4-byte user slot;
                // demand-paging resolves a not-present page on this CPL=0 write.
                unsafe { core::ptr::write_volatile(ctid as *mut i32, 0); }
                // FUTEX_WAKE | PRIVATE: clear_child_tid / pthread_join is
                // process-private, so it must key on (mm,va) to match the
                // joining thread's private FUTEX_WAIT.
                let _ = ipc::live::futex::dispatch(
                    ctid, 1 | ipc::live::futex::FUTEX_PRIVATE_FLAG, 1);
                task.clear_child_tid.store(0, Ordering::Release);
            }
            // Robust-futex recovery (Linux do_exit -> exit_robust_list): a
            // thread dying while holding a robust mutex must mark it
            // FUTEX_OWNER_DIED and wake a waiter, or a peer blocked on that lock
            // hangs forever (boot wedge: init parks in waitid behind a service
            // stuck on a dead owner's mutex). MUST run while the dying task's mm
            // is still mapped (before replace_mm below).
            let rl = task.robust_list_head.load(Ordering::Acquire);
            if rl != 0 {
                let vt = task.vtid.load(Ordering::Acquire);
                let owner_tid = if vt != 0 { vt } else { task.tid };
                ipc::live::futex::exit_robust_list(rl, owner_tid);
            }
            // B13/B14: drop fd_table+mm at exit + reparent children to init.
            // SAFETY: exiting task on this CPU; sole writer per single-mutator.
            unsafe { task.replace_fd_table(None); task.replace_mm(None); sched::live::reparent_children(task.tid); }
            sched::live::mark_done(task);
            debug_sched! {
                klog::write_raw(b"[INFO]  sys_exit: tid=");
                klog::write_dec_u64(task.tid as u64);
                klog::write_raw(b" code=");
                klog::write_dec_u64(args.a0);
                klog::write_raw(b"\n");
            }
            // A non-leader CLONE_THREAD exit (tid != tgid) is NOT a process
            // exit: Linux does not SIGCHLD the parent nor make it a
            // wait4-reapable zombie. pthread_join is served entirely by the
            // clear_child_tid FUTEX_WAKE above; the task is auto-released at
            // the schedule() switch drain (release_task). Only a process /
            // group-leader exit notifies the parent + parks a wait4 zombie.
            // Without this, every glib worker thread (polkitd, NetworkManager,
            // …) piled up as an unreapable zombie AND flooded its own process
            // with spurious SIGCHLD — stalling the polkit-authorized gdm
            // session setup so the greeter never launched.
            if task.tid == task.tgid.load(Ordering::Acquire) {
                sched::live::signal_child_exit(task);
            }
        }
    }
    // SAFETY: process ctx; preempt-off; Zombie state means no re-enqueue.
    unsafe { sched::live::schedule(); }
    // Unreachable — Zombie task isn't re-scheduled.
    loop { core::hint::spin_loop(); }
}
