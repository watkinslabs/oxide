// 443 quotactl_fd — one syscall, one file (docs/53 §0).
//
// Linux `quotactl_fd(int fd, unsigned cmd, int id, void *addr)`. Identical
// semantics to `quotactl(2)` (slot 179) except the target filesystem is named
// by an open fd rather than a `special` device path. Same cmd decode, same
// no-quota-active outcomes (see 179_quotactl.rs header).
//
// The fd IS validated (cheap, and a real Linux distinction: EBADF for a fd
// that does not resolve to an open file). No further inspection of the fd's
// filesystem is done — every valid target yields ESRCH/0 anyway.
#![cfg(target_os = "oxide-kernel")]

use syscall::{errno::Errno, SyscallArgs};

/// `sys_quotactl_fd(fd, cmd, id, addr)` — slot 443.
/// # C: O(1)
pub fn sys_quotactl_fd(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let cmd = args.a1;

    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU with preempt-off; no concurrent
    // fd_table writer exists for the current task's descriptor table here.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    if fdt.get(fd).is_err() { return -(Errno::Ebadf.as_i32() as i64); }

    crate::s179_quotactl::quotactl_dispatch(cmd)
}
