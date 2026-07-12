// 039 getpid — one syscall, one file (docs/53 §0).

use syscall::SyscallArgs;

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

/// `sys_getpid()` — slot 39. PID-namespace aware: returns the virtualized
/// vtgid when non-zero (non-init NS), else the real tgid. Init-NS tasks have
/// vtgid=0 → real tgid.
/// # C: O(1)
pub fn sys_getpid(_args: &SyscallArgs) -> i64 {
    current_task()
        .map(|c| c.visible_pid() as i64)
        .unwrap_or(1)
}
