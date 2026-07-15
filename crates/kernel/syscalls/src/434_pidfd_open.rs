// 434 pidfd_open — one syscall, one file (docs/53 §0). Moved verbatim from pidfd.rs.
#![cfg(target_os = "oxide-kernel")]

/// `sys_pidfd_open(pid, flags)` — allocates a pidfd bound to `pid`.
/// # C: O(N_tasks + N_fds)
pub fn sys_pidfd_open(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    const PIDFD_NONBLOCK: u64 = vfs::OpenFlags::O_NONBLOCK.bits() as u64;
    const PIDFD_THREAD: u64 = vfs::OpenFlags::O_EXCL.bits() as u64;
    if args.a1 & !(PIDFD_NONBLOCK | PIDFD_THREAD) != 0 || args.a0 as i32 <= 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let current = match sched::live::current() {
        Some(current) => current,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let options = pidfd::OpenOptions {
        nonblock: args.a1 & PIDFD_NONBLOCK != 0,
        thread: args.a1 & PIDFD_THREAD != 0,
    };
    match pidfd::open(current, args.a0 as u32, options) {
        Ok(fd) => fd as i64,
        Err(pidfd::OpenError::NotFound) => -(Errno::Esrch.as_i32() as i64),
        Err(pidfd::OpenError::NotLeader) => -(Errno::Enoent.as_i32() as i64),
        Err(pidfd::OpenError::BadFileTable) => -(Errno::Ebadf.as_i32() as i64),
        Err(pidfd::OpenError::Install(error)) => -(error as i64),
    }
}
