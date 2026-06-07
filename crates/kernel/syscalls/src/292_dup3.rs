// 292 dup3 — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_dup3(oldfd, newfd, flags)` — slot 292. Tier-3 shim.
/// Like dup2 but rejects oldfd==newfd; accepts O_CLOEXEC (ignored in v1).
/// # C: O(1) + close
pub fn sys_dup3(args: &SyscallArgs) -> i64 {
    const O_CLOEXEC: u64 = 0o2_000_000;
    let oldfd = args.a0 as i32;
    let newfd = args.a1 as i32;
    let flags = args.a2;
    if oldfd == newfd { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    match fdt.dup2(oldfd, newfd) {
        Ok(fd) => {
            if (flags & O_CLOEXEC) != 0 { let _ = fdt.set_cloexec(fd, true); }
            fd as i64
        }
        Err(e) => -(e as i64),
    }
}
