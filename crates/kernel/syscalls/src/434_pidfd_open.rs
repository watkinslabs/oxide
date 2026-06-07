// 434 pidfd_open — one syscall, one file (docs/53 §0). Moved verbatim from pidfd.rs.
#![cfg(target_os = "oxide-kernel")]

/// `sys_pidfd_open(pid, flags)` — allocates a pidfd bound to `pid`.
/// # C: O(N_fds)
pub fn sys_pidfd_open(args: &syscall::SyscallArgs) -> i64 {
    use alloc::string::ToString;
    use alloc::sync::Arc;
    use vfs::{Dentry, File, OpenFlags};
    use syscall::errno::Errno;
    const PIDFD_NONBLOCK: u64 = 0o0_004_000;
    let pid = args.a0 as u32;
    let flags = args.a1;
    // F109: pidfd_open with pid arg interpreted in caller's pid_ns.
    let cur_ns = sched::live::current()
        .map(|c| c.pid_ns.load(core::sync::atomic::Ordering::Acquire))
        .unwrap_or(0);
    if sched::live::registry::lookup_in_ns(cur_ns, pid).is_none() {
        return -(Errno::Esrch.as_i32() as i64);
    }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = crate::pidfd::new_pidfd_inode(pid);
    let dentry = Dentry::new(None, "pidfd".to_string(), Arc::clone(&inode));
    let mut fl = OpenFlags::O_RDWR;
    if (flags & PIDFD_NONBLOCK) != 0 { fl |= OpenFlags::O_NONBLOCK; }
    let file = File::new(inode, dentry, fl);
    match fdt.alloc(file) {
        Ok(fd)  => fd as i64,
        Err(e)  => -(e as i64),
    }
}
