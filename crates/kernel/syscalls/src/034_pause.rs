// 034 pause — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_pause()` — slot 34. Yield-loops until the calling task has
/// a non-masked signal pending, then returns -EINTR.
/// # C: O(yields)
pub fn sys_pause(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Eintr.as_i32() as i64),
    };
    loop {
        let pending = cur.sigpending.load(Ordering::Acquire);
        let masked  = cur.sigmask.load(Ordering::Acquire);
        if (pending & !masked) != 0 { return -(Errno::Eintr.as_i32() as i64); }
        // SAFETY: process ctx; runqueue installed.
        unsafe { sched::live::tick_yield(); }
    }
}
