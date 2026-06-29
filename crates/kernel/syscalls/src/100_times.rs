// 100 times — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::userbuf::validate_user_buf_writable;

/// `sys_times(tms)` — slot 100. utime + cutime real; stime +
/// cstime stay zero (kernel-time accounting follow-up).
/// # C: O(1)
pub fn sys_times(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use hal::TimerOps;
    let buf = args.a0;
    let now = {
        #[cfg(target_arch = "x86_64")]
        { hal_x86_64::X86TimerOps::monotonic_ns().0 }
        #[cfg(target_arch = "aarch64")]
        { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    };
    let (elapsed, children) = match sched::live::current() {
        Some(c) => (
            now.saturating_sub(c.spawn_ns.load(Ordering::Acquire)),
            c.cumulative_child_ns.load(Ordering::Acquire),
        ),
        None => (0, 0),
    };
    let utime_ticks  = sched::clock::ns_to_clk_tck(elapsed);
    let cutime_ticks = sched::clock::ns_to_clk_tck(children);
    if buf != 0 {
        if let Err(rv) = validate_user_buf_writable(buf, 32, 8) { return rv; }
        // SAFETY: validated 32-byte writable user buf; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile( buf       as *mut u64, utime_ticks);
            core::ptr::write_volatile((buf + 8)  as *mut u64, 0);             // stime
            core::ptr::write_volatile((buf + 16) as *mut u64, cutime_ticks);
            core::ptr::write_volatile((buf + 24) as *mut u64, 0);             // cstime
        }
    }
    sched::clock::ns_to_clk_tck(now) as i64
}
