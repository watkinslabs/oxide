// 124 getsid — one syscall, one file (docs/53 §0). ABI shim only.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_getsid(pid)` — slot 124. `pid == 0` means the caller; any other pid is
/// resolved in the caller's pid namespace (`sched::session::getsid`).
/// # C: O(log N_tasks) init-ns; O(N_tasks) otherwise
pub fn sys_getsid(args: &SyscallArgs) -> i64 {
    let cur = match sched::live::current() {
        Some(cur) => cur,
        None => return -(syscall::errno::Errno::Esrch.as_i32() as i64),
    };
    match sched::session::getsid(cur, args.a0 as i32) {
        Ok(sid) => sid as i64,
        Err(e) => -(e.as_i32() as i64),
    }
}
