// 100 times — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::userbuf::validate_user_buf_writable;

/// `sys_times(tms)` — slot 100. tms_utime/tms_stime are the caller's
/// tick-sampled user/kernel CPU time in CLK_TCK ticks; tms_cutime/
/// tms_cstime are the reaped children's cumulative user/kernel CPU time,
/// shared process-wide so a sibling thread's reap is visible here.
/// Return value = monotonic wall-clock in CLK_TCK ticks.
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
    let (utime_ns, stime_ns, cutime_ns, cstime_ns) = match sched::live::current() {
        Some(c) => (
            c.utime_ns.load(Ordering::Acquire),
            c.stime_ns.load(Ordering::Acquire),
            c.thread_group.child_acct().cpu_ns().0,
            c.thread_group.child_acct().cpu_ns().1,
        ),
        None => (0, 0, 0, 0),
    };
    let utime_ticks  = sched::clock::ns_to_clk_tck(utime_ns);
    let stime_ticks  = sched::clock::ns_to_clk_tck(stime_ns);
    let cutime_ticks = sched::clock::ns_to_clk_tck(cutime_ns);
    let cstime_ticks = sched::clock::ns_to_clk_tck(cstime_ns);
    if buf != 0 {
        if let Err(rv) = validate_user_buf_writable(buf, 32, 1) { return rv; }
        // SAFETY: validated 32-byte writable user buf; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_unaligned( buf       as *mut u64, utime_ticks);
            core::ptr::write_unaligned((buf + 8)  as *mut u64, stime_ticks);
            core::ptr::write_unaligned((buf + 16) as *mut u64, cutime_ticks);
            core::ptr::write_unaligned((buf + 24) as *mut u64, cstime_ticks);
        }
    }
    sched::clock::ns_to_clk_tck(now) as i64
}
