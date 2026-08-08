// 438 pidfd_getfd — one syscall, one file (docs/53 §0). Moved verbatim from pidfd.rs.
#![cfg(target_os = "oxide-kernel")]

/// `sys_pidfd_getfd(pidfd, targetfd, flags)` — slot 438. Clones the
/// target task's fd into the calling task's fd table. Used by sandbox
/// programs (e.g. systemd-machined) that need to manipulate fds in
/// another process.
///
/// Linux semantics:
///   * `flags` must be 0 (any non-zero is EINVAL).
///   * pidfd must be a valid pidfd inode.
///   * Target task's targetfd must be open.
///   * Returns a new fd referring to the same Arc<File> (shared open
///     file description, so cursor + flock state are shared with the
///     target task — exactly what callers expect for fd-passing).
/// # C: O(N_fds)
pub fn sys_pidfd_getfd(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let pidfd     = args.a0 as i32;
    let target_fd = args.a1 as i32;
    let flags     = args.a2 as u32;
    if flags != 0 { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot for cur.
    let cur_fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let pidfd_file = match cur_fdt.get(pidfd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let identity = match pidfd::identity_from_inode(&pidfd_file.inode()) {
        Some(identity) => identity,
        None => return -(Errno::Einval.as_i32() as i64),
    };
    let target = match identity.task() {
        Some(target) => target,
        None => return -(Errno::Esrch.as_i32() as i64),
    };
    // Linux `__pidfd_fget` holds the target's `exec_update_lock` for READING
    // across BOTH the access check and the fd fetch. Without it the two halves
    // straddle a concurrent `execve` on the target: the check passes against
    // the pre-exec credentials, the target then execs a setuid image (or drops
    // dumpability), and the fetch hands over an fd from a process the caller is
    // no longer allowed to touch.
    // SAFETY: syscall process context, no spinlock held; sleeps only while the target is mid-execve.
    let _exec_update = unsafe { target.thread_group.exec_update_read() };
    if crate::s101_ptrace_perm::may_attach_access(&cur, &target).is_err() {
        return -(Errno::Eperm.as_i32() as i64);
    }
    if target.state() == sched::task::TaskState::Zombie {
        return -(Errno::Esrch.as_i32() as i64);
    }
    // target task may be running (or exiting) on another CPU: clone_fd_table
    // pins against a concurrent replace_fd_table(None) at exit so this
    // Arc<FdTable> snapshot can't race a UAF.
    let target_fdt = match target.clone_fd_table() {
        Some(t) => t, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let cloned = match target_fdt.get(target_fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    drop(_exec_update);
    match cur_fdt.alloc_limit(cloned, cur.nofile_soft()) {
        Ok(fd) => {
            let _ = cur_fdt.set_cloexec(fd, true);
            fd as i64
        }
        Err(e) => -(e as i64),
    }
}

// The access gate is the ATTACH-class ladder — Linux
// `ptrace_may_access(PTRACE_MODE_ATTACH_REALCREDS)`. This file used to carry its
// own open-coded copy of the cred ladder, which OMITTED the dumpability gate:
// `__ptrace_may_access` requires `CAP_SYS_PTRACE` when the target is
// non-dumpable, so a process that dropped privileges (setuid exec, or
// `prctl(PR_SET_DUMPABLE, 0)`) could still have its fds stolen by the uid that
// launched it. A second copy of a security ladder is exactly the split source of
// truth that lets one side rot.
