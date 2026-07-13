use syscall::{errno::Errno, SyscallArgs};

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

/// `sys_quotactl_fd(fd, cmd, id, addr)` — slot 443. # C: O(1)+FS
pub fn sys_quotactl_fd(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let cmd = args.a1 as u32 as u64;
    let id = args.a2;
    let addr = args.a3;

    let cur = match current_task() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU with preempt-off; no concurrent
    // fd_table writer exists for the current task's descriptor table here.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    crate::s443_quotactl_fd::quotactl_fd_file(&file, cmd, id, addr)
}
