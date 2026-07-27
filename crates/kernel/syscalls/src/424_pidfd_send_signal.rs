// 424 pidfd_send_signal — one syscall, one file (docs/53 §0). Moved verbatim from pidfd.rs.
#![cfg(target_os = "oxide-kernel")]

/// `sys_pidfd_send_signal(pidfd, sig, info, flags)` — slot 424.
/// Resolves the pidfd's bound tid via the inode marker and posts
/// the signal bit into that task's sigpending.
/// # C: O(N_tasks)
pub fn sys_pidfd_send_signal(args: &syscall::SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    use sched::Signum;
    const PIDFD_SIGNAL_THREAD:        u64 = 1 << 0;
    const PIDFD_SIGNAL_THREAD_GROUP:  u64 = 1 << 1;
    const PIDFD_SIGNAL_PROCESS_GROUP: u64 = 1 << 2;
    const PIDFD_SIGNAL_FLAGS: u64 = PIDFD_SIGNAL_THREAD | PIDFD_SIGNAL_THREAD_GROUP | PIDFD_SIGNAL_PROCESS_GROUP;
    let fd  = args.a0 as i32;
    let sig = args.a1 as i32;
    let info = args.a2;
    let flags = args.a3;
    if !(0..=64).contains(&sig) { return -(Errno::Einval.as_i32() as i64); }
    if (flags & !PIDFD_SIGNAL_FLAGS) != 0 { return -(Errno::Einval.as_i32() as i64); }
    if (flags & PIDFD_SIGNAL_FLAGS).count_ones() > 1 { return -(Errno::Einval.as_i32() as i64); }
    if info != 0 {
        if let Err(rv) = crate::userbuf::validate_user_buf(info, 32, 1) { return rv; }
        // SAFETY: info validated readable for leading siginfo_t fields; si_signo is the first i32.
        let signo = unsafe { core::ptr::read_unaligned(info as *const i32) };
        if signo != sig { return -(Errno::Einval.as_i32() as i64); }
    }
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
    let identity = match pidfd::identity_from_inode(&file.inode()) {
        Some(identity) => identity,
        None => return -(Errno::Einval.as_i32() as i64),
    };
    let task = match identity.task() {
        Some(task) => task,
        None => return -(Errno::Esrch.as_i32() as i64),
    };
    if task.reaped.load(Ordering::Acquire) {
        return -(Errno::Esrch.as_i32() as i64);
    }
    let scope = if (flags & PIDFD_SIGNAL_THREAD) != 0
        || ((flags & PIDFD_SIGNAL_FLAGS) == 0 && file.flags().contains(vfs::OpenFlags::O_EXCL)) {
        PIDFD_SIGNAL_THREAD
    } else if (flags & PIDFD_SIGNAL_PROCESS_GROUP) != 0 {
        PIDFD_SIGNAL_PROCESS_GROUP
    } else {
        PIDFD_SIGNAL_THREAD_GROUP
    };
    let bit = if sig == 0 { 0 } else { 1u64 << (sig - 1) };
    let mut live = 0usize;
    let mut permitted = 0usize;
    let tasks = match sched::registry::try_snapshot() { Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64) };
    for t in &tasks {
        if t.reaped.load(Ordering::Acquire) { continue; }
        let hit = if scope == PIDFD_SIGNAL_THREAD {
            t.tid == task.tid
        } else if scope == PIDFD_SIGNAL_PROCESS_GROUP {
            t.pgid() == task.pgid()
        } else {
            t.vtgid.load(Ordering::Acquire) == task.vtgid.load(Ordering::Acquire)
        };
        if !hit { continue; }
        live += 1;
        if !crate::signal::sig_perm_check(cur, t, sig) { continue; }
        permitted += 1;
        if sig != 0 {
            t.sigpending.fetch_or(bit, Ordering::Release);
            if sig == Signum::Sigcont as i32 { sched::live::registry::wake_if_stopped(t); }
            sched::live::signal_wake_up(t);
        }
    }
    if live == 0 { -(Errno::Esrch.as_i32() as i64) }
    else if permitted == 0 { -(Errno::Eperm.as_i32() as i64) }
    else { 0 }
}
