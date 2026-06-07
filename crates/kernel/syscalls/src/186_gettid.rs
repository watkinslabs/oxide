// 186 gettid — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_gettid()` — slot 186. Returns the current task's `tid`.
/// PID-NS-virtualized; tasks in init NS see real tid.
/// # C: O(1)
pub fn sys_gettid(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    sched::live::current().map(|c| {
        let v = c.vtid.load(Ordering::Acquire);
        if v != 0 { v as i64 } else { c.tid as i64 }
    }).unwrap_or(1)
}
