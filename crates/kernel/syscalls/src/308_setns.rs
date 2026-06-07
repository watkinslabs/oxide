// 308 setns — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_setns(fd, nstype)` — slot 308. F117: real downcast of fd's
/// inode to NsInode (per `26§R01`); validates kind, writes the
/// captured ns id into the calling task's matching slot.
/// # C: O(1)
pub fn sys_setns(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let fd     = args.a0 as i32;
    let nstype = args.a1;
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = file.inode();
    let any = match inode.as_any() {
        Some(a) => a, None => return -(Errno::Einval.as_i32() as i64),
    };
    let ns = match any.downcast_ref::<nscg::proc_ns::NsInode>() {
        Some(n) => n, None => return -(Errno::Einval.as_i32() as i64),
    };
    nscg::proc_ns::setns_apply(ns, nstype, cur)
}
