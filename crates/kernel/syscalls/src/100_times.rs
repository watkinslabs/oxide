// 100 times — one syscall, one file (docs/53 §0). The `struct tms` layout,
// the NULL-buffer rule and the return-value contract are pure and live in
// `syscall::rusage`, which is where they are asserted.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::rusage::{times_wants_tms, Tms, TMS_BYTES};
use crate::userbuf::validate_user_buf_writable;

/// `sys_times(tms)` — slot 100.
///
/// `tms_utime`/`tms_stime` are the calling PROCESS's user/kernel CPU time —
/// the whole thread group, so a `time` builtin sees what its worker threads
/// spent and keeps seeing it after they exit. `tms_cutime`/`tms_cstime` are
/// the reaped children's cumulative time, likewise process-wide so a sibling
/// thread's reap is visible here. All four are CLK_TCK ticks, the same
/// `AT_CLKTCK` the auxv advertises to `sysconf(_SC_CLK_TCK)`.
///
/// A NULL `tms` is legal: the copy-out is skipped and the tick count is still
/// returned. The return is a tick count, never a status.
/// # C: O(1)
pub fn sys_times(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    let buf = args.a0;
    let now = {
        #[cfg(target_arch = "x86_64")]
        { hal_x86_64::X86TimerOps::monotonic_ns().0 }
        #[cfg(target_arch = "aarch64")]
        { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    };
    if times_wants_tms(buf) {
        let t = match sched::live::current() {
            Some(c) => {
                let (utime_ns, stime_ns) = c.thread_group.cpu_sample();
                let (cutime_ns, cstime_ns) = c.thread_group.child_acct().cpu_ns();
                Tms {
                    utime_ticks:  sched::clock::ns_to_clk_tck(utime_ns),
                    stime_ticks:  sched::clock::ns_to_clk_tck(stime_ns),
                    cutime_ticks: sched::clock::ns_to_clk_tck(cutime_ns),
                    cstime_ticks: sched::clock::ns_to_clk_tck(cstime_ns),
                }
            }
            None => Tms::default(),
        };
        if let Err(rv) = validate_user_buf_writable(buf, TMS_BYTES as u64, 1) { return rv; }
        let bytes = t.encode();
        // SAFETY: validated writable user buf of exactly TMS_BYTES; CPL=0 write through the caller's AS.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, TMS_BYTES); }
    }
    sched::clock::ns_to_clk_tck(now) as i64
}
