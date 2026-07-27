// 186 gettid — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_gettid()` — slot 186. Linux `kernel/sys.c`:
///     return task_pid_vnr(current);
///
/// The THREAD id in the caller's pid namespace — not `tgid` (that is
/// `getpid(2)`) and not a global id. `vtid == 0` means the task has no
/// namespace-local number yet, i.e. it is in the initial namespace where the
/// internal tid IS the visible one. Never fails.
/// # C: O(1)
pub fn sys_gettid(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    sched::live::current().map(|c| {
        let v = c.vtid.load(Ordering::Acquire);
        if v != 0 { v as i64 } else { c.tid as i64 }
    }).unwrap_or(1)
}
