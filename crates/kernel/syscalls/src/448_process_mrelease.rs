// 448 process_mrelease — one syscall, one file (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;

/// process_mrelease(pidfd, flags).
/// # C: O(1)
pub fn sys_process_mrelease(args: &SyscallArgs) -> i64 {
    let cur = match sched::live::current() { Some(c) => c, None => return errno(Errno::Ebadf) };
    // SAFETY: fd_table slot single-mutator per `13§5`; running task on this CPU; clone Arc.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return errno(Errno::Ebadf) };
    if fdt.get(args.a0 as i32).is_err() { return errno(Errno::Ebadf); }
    0
}
