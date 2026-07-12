// 036 getitimer — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::userbuf::validate_user_buf_writable;

const ITIMER_REAL:    u64 = 0;
const ITIMER_VIRTUAL: u64 = 1;
const ITIMER_PROF:    u64 = 2;
const ITIMERVAL_SIZE: u64 = 32;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn now_mono_ns() -> u64 {
    #[cfg(target_arch = "x86_64")] { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")] { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

fn remain(deadline: u64, now: u64) -> u64 {
    if deadline > now { deadline - now } else { 0 }
}

/// `sys_getitimer(which, curr)` — slot 36.
/// # C: O(1)
pub fn sys_getitimer(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let which = args.a0;
    let curr = args.a1;
    if !matches!(which, ITIMER_REAL | ITIMER_VIRTUAL | ITIMER_PROF) { return err(Errno::Einval); }
    if let Err(rv) = validate_user_buf_writable(curr, ITIMERVAL_SIZE, 1) { return rv; }
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    let (interval, rem) = match which {
        ITIMER_REAL => {
            let dl = cur.alarm_ns.load(Ordering::Acquire);
            (cur.alarm_interval_ns.load(Ordering::Acquire), remain(dl, now_mono_ns()))
        }
        ITIMER_VIRTUAL => {
            let now = cur.utime_ns.load(Ordering::Acquire);
            let dl = cur.itimer_virtual_ns.load(Ordering::Acquire);
            (cur.itimer_virtual_interval_ns.load(Ordering::Acquire), remain(dl, now))
        }
        _ => {
            let now = cur.utime_ns.load(Ordering::Acquire).saturating_add(cur.stime_ns.load(Ordering::Acquire));
            let dl = cur.itimer_prof_ns.load(Ordering::Acquire);
            (cur.itimer_prof_interval_ns.load(Ordering::Acquire), remain(dl, now))
        }
    };
    let (i_s, i_us) = sched::clock::ns_to_timeval(interval);
    let (r_s, r_us) = sched::clock::ns_to_timeval(rem);
    // SAFETY: curr validated writable; CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_unaligned( curr       as *mut u64, i_s);
        core::ptr::write_unaligned((curr +  8) as *mut u64, i_us);
        core::ptr::write_unaligned((curr + 16) as *mut u64, r_s);
        core::ptr::write_unaligned((curr + 24) as *mut u64, r_us);
    }
    0
}
