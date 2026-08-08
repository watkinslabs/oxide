// 077 ftruncate — one syscall, one file (docs/53 §0). ABI shim only: the size
// change itself is `fs::truncate::do_ftruncate`.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_ftruncate(fd, length)` — slot 77.
/// # C: O(1)
pub fn sys_ftruncate(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let len = args.a1;
    // Linux `ksys_ftruncate`: negative length → EINVAL, ahead of the fd lookup (D34).
    if (len as i64) < 0 { return -(Errno::Einval.as_i32() as i64); }
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
    // Truncation is decided by the rights recorded when this description was
    // opened, not by the caller's current domain: an fd passed between
    // processes keeps the rights it was opened with, and a thread that
    // sandboxes itself after an open does not lose them.
    if !::landlock::access::truncate_allowed(file.landlock_access()) {
        return -(Errno::Eacces.as_i32() as i64);
    }
    ::fs::truncate::do_ftruncate(&file, len, &crate::pathresolve::current_cred())
}
