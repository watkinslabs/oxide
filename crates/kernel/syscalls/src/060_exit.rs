// 060 exit — one syscall, one file (docs/53 §0). Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

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
            task.exit_status.store(args.a0 as i32, Ordering::Release);
            task.vfork_pending.store(false, Ordering::Release); // F156 vfork
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
            if ctid != 0 && ctid < hal::USER_VA_END {
                // SAFETY: ctid validated < USER_VA_END; CPL=0 write through caller's AS.
                unsafe { core::ptr::write_volatile(ctid as *mut i32, 0); }
                let _ = ipc::live::futex::dispatch(ctid, 1 /* FUTEX_WAKE */, 1);
                task.clear_child_tid.store(0, Ordering::Release);
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
            sched::live::signal_child_exit(task);
        }
    }
    // SAFETY: process ctx; preempt-off; Zombie state means no re-enqueue.
    unsafe { sched::live::schedule(); }
    // Unreachable — Zombie task isn't re-scheduled.
    loop { core::hint::spin_loop(); }
}
