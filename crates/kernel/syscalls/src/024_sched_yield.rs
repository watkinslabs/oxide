// 024 sched_yield — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_sched_yield()` — slot 24. tick_yield + 0.
/// # C: O(log N)
pub fn sys_sched_yield(_args: &SyscallArgs) -> i64 {
    // DIAG (debug-syscall): a process spinning on sched_yield (the boot wedge)
    // never makes progress. Log the caller's user RIP every Nth yield so the
    // spin loop can be symbolized (which lock/condition it busy-waits on).
    #[cfg(feature = "debug-syscall")]
    {
        use core::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let c = N.fetch_add(1, Ordering::Relaxed);
        if c % 20000 == 0 {
            // SAFETY: current_user_frame()[0] is the saved user RIP on this task's syscall kstack.
            let rip = unsafe { (*hal_x86_64::current_user_frame())[0] };
            let tid = sched::live::current().map(|t| t.tid).unwrap_or(0);
            klog::write_raw(b"[mnt] YIELD-SPIN rip="); klog::write_hex_u64(rip);
            klog::write_raw(b" tid=");                 klog::write_dec_u64(tid as u64);
            klog::write_raw(b"\n");
        }
    }
    if sched::live::global().is_some() {
        // SAFETY: process ctx; runqueue installed; preempt-off through the syscall handler; tick_yield saves into current.arch_ctx + Context::switch's away.
        unsafe { sched::live::tick_yield(); }
    }
    0
}
