// 039 getpid — one syscall, one file (docs/53 §0).

use core::sync::atomic::Ordering;
use syscall::SyscallArgs;

/// `sys_getpid()` — slot 39. PID-namespace aware: returns the virtualized
/// vtgid when non-zero (non-init NS), else the real tgid. Init-NS tasks have
/// vtgid=0 → real tgid.
/// # C: O(1)
pub fn sys_getpid(_args: &SyscallArgs) -> i64 {
    sched::live::current()
        .map(|c| {
            let v = c.vtgid.load(Ordering::Acquire);
            if v != 0 { v as i64 } else { c.tgid.load(Ordering::Acquire) as i64 }
        })
        .unwrap_or(1)
}
