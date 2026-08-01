// 434 pidfd_open — one syscall, one file (docs/53 §0). Moved verbatim from pidfd.rs.
#![cfg(target_os = "oxide-kernel")]

/// `sys_pidfd_open(pid, flags)` — allocates a pidfd bound to `pid`.
/// # C: O(N_tasks + N_fds)
pub fn sys_pidfd_open(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let (pid, options) = match pidfd::admit(args.a0, args.a1) {
        Ok(admitted) => admitted,
        Err(errno) => return -(errno.as_i32() as i64),
    };
    let current = match sched::live::current() {
        Some(current) => current,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    match pidfd::open(current, pid, options) {
        Ok(fd) => fd as i64,
        Err(pidfd::OpenError::NotFound) => -(Errno::Esrch.as_i32() as i64),
        Err(pidfd::OpenError::NotLeader) => -(Errno::Enoent.as_i32() as i64),
        Err(pidfd::OpenError::BadFileTable) => -(Errno::Ebadf.as_i32() as i64),
        Err(pidfd::OpenError::Install(error)) => -(error as i64),
    }
}
