// 032 dup — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_dup(oldfd)` — slot 32. Tier-3 shim per `docs/53§4`.
/// Work fn: `vfs::FdTable::dup`. Lowest free fd → same File.
/// # C: O(N_fds)
pub fn sys_dup(args: &SyscallArgs) -> i64 {
    let oldfd = args.a0 as i32;
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    match fdt.dup(oldfd) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}
