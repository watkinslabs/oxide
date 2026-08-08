// 308 setns — one syscall, one file (docs/53 §0). ABI shim: classify the fd
// (nsfs file vs pidfd), then hand off. The per-namespace install ladder lives
// in `nscg::proc_ns::setns_perm`; the pidfd flag vocabulary lives in
// `crate::setns_flags` (non-gated, hosted-tested).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

#[path = "308_setns/from_pidfd.rs"]
mod from_pidfd;

/// `sys_setns(fd, nstype)` — `SYSCALL_DEFINE2(setns)`.
///
/// Two fd shapes, as Linux: an `/proc/<pid>/ns/*` (nsfs) fd installs exactly
/// that one namespace, and `nstype` — when non-zero — must name its type; a
/// pidfd installs EVERY namespace named in `nstype`, taken from the target
/// process. Anything else is `EINVAL`.
/// # C: O(1) for an nsfs fd; O(bits) for a pidfd
pub fn sys_setns(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let fd     = args.a0 as i32;
    let nstype = args.a1;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    if file.inode().private::<nscg::NsInode>().is_some() {
        return nscg::setns_from_fd(&fdt, fd, nstype, cur);
    }
    match ::pidfd::task_from_inode(file.inode()) {
        Some(target) => from_pidfd::install(&target, nstype, cur),
        None => -(Errno::Einval.as_i32() as i64),
    }
}
