// sys_clock_nanosleep per docs/15§5. Extracted from proc.rs to
// keep that file under the 1000-line cap.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::userbuf::validate_user_buf;
use crate::time_common::{clock_id_known, clock_nanosleep_supported,
    current_sleep_target_to_host, ns_for_clock};

const TIMER_ABSTIME: u64 = 0x1;

/// `sys_clock_nanosleep(clk_id, flags, req, rem)` — slot 230.
///
/// Linux `SYSCALL_DEFINE4(clock_nanosleep)` (`kernel/time/posix-timers.c:1383`)
/// → `common_nsleep`/`common_nsleep_timens` → `hrtimer_nanosleep`, in this
/// order: clock admission (EINVAL / EOPNOTSUPP), `get_timespec64` (EFAULT),
/// `timespec64_valid` (EINVAL), then
///   `if (flags & TIMER_ABSTIME) rmtp = NULL;`
///   `current->restart_block.fn = do_no_restart_syscall;`
/// so the ABSTIME form can never copy remaining time out and can never leave a
/// stale continuation armed. The sleep itself, the deliverable-signal triage
/// and the interrupted tail are the SAME engine `nanosleep(2)` uses
/// (`crate::s035_nanosleep::sleep_until_deadline`) — this slot only converts
/// the clock + flags into an absolute monotonic deadline.
/// # C: O(1) + sleep cost
pub fn sys_clock_nanosleep(args: &SyscallArgs) -> i64 {
    let clk_id = args.a0;
    let flags = args.a1;
    let req   = args.a2;
    if !clock_id_known(clk_id) {
        return -(Errno::Einval.as_i32() as i64);
    }
    if !clock_nanosleep_supported(clk_id) {
        return -(Errno::Eopnotsupp.as_i32() as i64);
    }
    if crate::time_common::clock_is_alarm(clk_id) {
        let Some(cur) = sched::live::current() else {
            return -(Errno::Esrch.as_i32() as i64);
        };
        if !cur.has_cap(sched::cap::WAKE_ALARM) {
            return -(Errno::Eperm.as_i32() as i64);
        }
    }
    if let Err(rv) = validate_user_buf(req, 16, 1) { return rv; }
    // SAFETY: req validated as readable 16-byte timespec storage.
    let (secs, nsec) = unsafe {
        let s = core::ptr::read_unaligned(req as *const i64);
        let n = core::ptr::read_unaligned((req + 8) as *const i64);
        (s, n)
    };
    // `ktime_set`-clamped decode: TIMER_ABSTIME with a huge-but-valid tv_sec
    // clamps to KTIME_MAX_NS instead of an unbounded absolute deadline.
    let target_ns = match ::syscall::time::timespec_to_ns(secs, nsec) {
        Ok(ns) => ns,
        Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let is_abs = (flags & TIMER_ABSTIME) != 0;
    // `posix-timers.c:1400-1401`: TIMER_ABSTIME forces `rmtp = NULL`, which
    // makes `restart->nanosleep.type` TT_NONE — that is what stops
    // `do_nanosleep` copying any remainder out for the absolute form.
    let rem = if is_abs { 0 } else { args.a3 };
    let host_target = match current_sleep_target_to_host(clk_id, is_abs, target_ns) {
        Ok(ns) => ns,
        Err(_) => return -(Errno::Eio.as_i32() as i64),
    };
    let rel_ns = if is_abs {
        let host_now = ns_for_clock(clk_id);
        if host_target <= host_now { return 0; }
        host_target - host_now
    } else {
        host_target
    };
    let deadline = monotonic().saturating_add(rel_ns);
    let Some(cur) = sched::live::current() else { return 0; };
    // Linux `current->restart_block.fn = do_no_restart_syscall` at entry: a
    // fresh sleep must not inherit the previous call's continuation, and the
    // ABSTIME arm never re-arms one.
    cur.restart_block.disarm();
    crate::s035_nanosleep::sleep_until_deadline(cur, deadline, rem, is_abs)
}

#[inline]
fn monotonic() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}
