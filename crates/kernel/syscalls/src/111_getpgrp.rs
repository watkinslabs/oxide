// 111 getpgrp — one syscall, one file (docs/53 §0). ABI shim only.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_getpgrp()` — slot 111. Linux defines it as `do_getpgid(0)`, so it
/// routes to the same work fn `getpgid(2)` uses with `pid == 0`, which cannot
/// fail.
/// # C: O(1)
pub fn sys_getpgrp(_args: &SyscallArgs) -> i64 {
    let cur = match sched::live::current() {
        Some(cur) => cur,
        None => return -(syscall::errno::Errno::Esrch.as_i32() as i64),
    };
    match sched::session::getpgid(cur, 0) {
        Ok(pgid) => pgid as i64,
        Err(e) => -(e.as_i32() as i64),
    }
}
