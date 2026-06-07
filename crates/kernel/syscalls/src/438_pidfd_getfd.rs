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
    let tid = match crate::pidfd::tid_from_ino(pidfd_file.inode().ino()) {
        Some(t) => t, None => return -(Errno::Einval.as_i32() as i64),
    };
    let target = match sched::live::registry::lookup(tid) {
        Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // SAFETY: target task may be running on another CPU but fd_table
    // pointer is set once at spawn (or via replace_fd_table at execve);
    // Arc<FdTable> Acquire snapshot is safe under per-task UP invariant.
    let target_fdt = match unsafe { target.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let cloned = match target_fdt.get(target_fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    match cur_fdt.alloc(cloned) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}
