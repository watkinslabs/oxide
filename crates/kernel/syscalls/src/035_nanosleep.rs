// 035 nanosleep — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

/// `sys_nanosleep(req, rem)` — slot 35. yield-loop on monotonic clock.
/// # C: O(req_ns / yield_quantum)
pub fn sys_nanosleep(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    use syscall::errno::Errno;
    let req = args.a0;
    if let Err(rv) = validate_user_buf(req, 16, 8) { return rv; }
    // SAFETY: req validated as readable 16-byte timespec storage.
    let secs = unsafe { core::ptr::read_volatile(req as *const i64) };
    // SAFETY: req+8 is inside the validated timespec storage.
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
    let rem = args.a1;
    let cur = sched::live::current();
    while now() < deadline {
        // Interruptible: an unblocked pending signal aborts the sleep with
        // EINTR and writes the remaining time to `rem` (Linux nanosleep). Mirror
        // of the poll/pselect6 EINTR check. Without this, `sleep` could not be
        // interrupted by Ctrl-C / SIGTERM until the full duration elapsed.
        if let Some(c) = cur {
            use core::sync::atomic::Ordering;
            let pending = c.sigpending.load(Ordering::Acquire);
            let mask    = c.sigmask.load(Ordering::Acquire);
            if pending & !mask != 0 {
                if rem != 0 {
                    if let Err(rv) = validate_user_buf_writable(rem, 16, 8) { return rv; }
                    let left  = deadline.saturating_sub(now());
                    let rsec  = (left / 1_000_000_000) as i64;
                    let rnsec = (left % 1_000_000_000) as i64;
                    // SAFETY: rem validated writable for a 16-byte timespec.
                    unsafe {
                        core::ptr::write_volatile(rem as *mut i64, rsec);
                        core::ptr::write_volatile((rem + 8) as *mut i64, rnsec);
                    }
                }
                return -(Errno::Eintr.as_i32() as i64);
            }
        }
        if sched::live::global().is_some() {
            // SAFETY: process ctx; runqueue installed; preempt-off through the syscall handler; tick_yield saves into current.arch_ctx + Context::switch's away.
            unsafe { sched::live::tick_yield(); }
        } else {
            core::hint::spin_loop();
        }
    }
    0
}
