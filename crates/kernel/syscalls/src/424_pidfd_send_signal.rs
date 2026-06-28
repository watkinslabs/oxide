// 424 pidfd_send_signal — one syscall, one file (docs/53 §0). Moved verbatim from pidfd.rs.
#![cfg(target_os = "oxide-kernel")]

/// `sys_pidfd_send_signal(pidfd, sig, info, flags)` — slot 424.
/// Resolves the pidfd's bound tid via the inode marker and posts
/// the signal bit into that task's sigpending.
/// # C: O(N_tasks)
pub fn sys_pidfd_send_signal(args: &syscall::SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let fd  = args.a0 as i32;
    let sig = args.a1 as i32;
    if !(1..=64).contains(&sig) { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let task = match crate::pidfd::task_from_inode(&file.inode()) {
        Some(t) => t, None => return -(Errno::Einval.as_i32() as i64),
    };
    if !crate::signal::sig_perm_check(cur, &task, sig) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    task.sigpending.fetch_or(1u64 << (sig - 1), Ordering::Release);
    // F168 (pidfd path): posting the bit is not enough — a target parked
    // Sleeping in an interruptible blocking syscall (e.g. wait4's
    // park_for_wait4, which sets TaskState::Sleeping) must be woken so it
    // re-checks pending, returns -EINTR, and runs the syscall-return
    // dispatch tail that performs the SIG_DFL terminate. sys_kill (062) and
    // tgkill (234) already do this; pidfd_send_signal was the only sender
    // that set the bit without a wake — so systemd's pidfd-based
    // SIGTERM/SIGABRT/SIGKILL never woke a wait4-parked child, leaving it
    // unkillable (journald fork-child / sd-executor survive escalation).
    if sig == 18 { sched::live::registry::wake_if_stopped(&task); }
    sched::live::wake_if_sleeping(&task);
    0
}
