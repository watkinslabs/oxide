// 112 setsid — one syscall, one file (docs/53 §0). ABI shim only.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_setsid()` — slot 112. Semantics and the two EPERM conditions live in
/// `sched::session::setsid`.
/// # C: O(N_tasks)
pub fn sys_setsid(_args: &SyscallArgs) -> i64 {
    let cur = match sched::live::current() {
        Some(cur) => cur,
        None => return -(syscall::errno::Errno::Eperm.as_i32() as i64),
    };
    match sched::session::setsid(cur) {
        Ok(sid) => sid as i64,
        Err(e) => -(e.as_i32() as i64),
    }
}
