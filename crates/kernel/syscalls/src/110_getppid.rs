// 110 getppid — one syscall, one file (docs/53 §0). ABI shim only.

use syscall::SyscallArgs;

/// `sys_getppid()` — slot 110. Semantics in `sched::session::getppid`: the
/// parent's PROCESS id as seen in the caller's pid namespace, 0 when the parent
/// has no number there (Linux `task_tgid_vnr(real_parent)`).
/// # C: O(log N_tasks)
pub fn sys_getppid(_args: &SyscallArgs) -> i64 {
    let cur = match sched::live::current() { Some(cur) => cur, None => return 0 };
    sched::session::getppid(cur) as i64
}
