// 035 nanosleep — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_nanosleep(req, rem)` — slot 35. yield-loop on monotonic clock.
/// # C: O(req_ns / yield_quantum)
pub fn sys_nanosleep(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    use syscall::errno::Errno;
    let req = args.a0;
    if req == 0 || req >= hal::USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    // SAFETY: req validated < USER_VA_END; user page mapped (caller's AS); CPL=0 reads via active CR3.
    let secs = unsafe { core::ptr::read_volatile(req as *const i64) };
    // SAFETY: same validated range; tv_nsec at +8 is 8-byte aligned per Linux ABI.
    let nsec = unsafe { core::ptr::read_volatile((req + 8) as *const i64) };
    if secs < 0 || nsec < 0 || nsec >= 1_000_000_000 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let total = (secs as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64);
    #[cfg(target_arch = "x86_64")]
    let now = || hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let now = || hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let start = now();
    let deadline = start.saturating_add(total);
    while now() < deadline {
        if sched::live::global().is_some() {
            // SAFETY: process ctx; runqueue installed; preempt-off through the syscall handler; tick_yield saves into current.arch_ctx + Context::switch's away.
            unsafe { sched::live::tick_yield(); }
        } else {
            core::hint::spin_loop();
        }
    }
    0
}
