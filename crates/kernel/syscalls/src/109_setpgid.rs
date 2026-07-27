// 109 setpgid — one syscall, one file (docs/53 §0). ABI shim only: decode the
// two pid_t args, call the sched work fn, encode the errno.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_setpgid(pid, pgid)` — slot 109. Semantics and full error ladder live in
/// `sched::session::setpgid`.
/// # C: O(N_tasks)
pub fn sys_setpgid(args: &SyscallArgs) -> i64 {
    let cur = match sched::live::current() {
        Some(cur) => cur,
        None => return -(syscall::errno::Errno::Esrch.as_i32() as i64),
    };
    match sched::session::setpgid(cur, args.a0 as i32, args.a1 as i32) {
        Ok(()) => 0,
        Err(e) => -(e.as_i32() as i64),
    }
}
