// 038 setitimer — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

const ITIMER_REAL:    u64 = 0;
const ITIMER_VIRTUAL: u64 = 1;
const ITIMER_PROF:    u64 = 2;
const ITIMERVAL_SIZE: u64 = 32;
const USEC_PER_SEC:   i64 = 1_000_000;
const NSEC_PER_SEC:   u64 = 1_000_000_000;
const NSEC_PER_USEC:  u64 = 1_000;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn now_mono_ns() -> u64 {
    #[cfg(target_arch = "x86_64")] { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")] { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

fn timeval_to_ns(sec: i64, usec: i64) -> Result<u64, i64> {
    if sec < 0 || !(0..USEC_PER_SEC).contains(&usec) { return Err(err(Errno::Einval)); }
    let s = (sec as u64).checked_mul(NSEC_PER_SEC).ok_or_else(|| err(Errno::Einval))?;
    let u = (usec as u64).checked_mul(NSEC_PER_USEC).ok_or_else(|| err(Errno::Einval))?;
    s.checked_add(u).ok_or_else(|| err(Errno::Einval))
}

fn read_itimerval(ptr: u64) -> Result<(u64, u64), i64> {
    if ptr == 0 { return Ok((0, 0)); }
    validate_user_buf(ptr, ITIMERVAL_SIZE, 1)?;
    // Linux `copy_from_user`: the range check proves the number is small
    // enough, not that the page is there, so the copy goes through the
    // exception table and an unmapped address answers EFAULT.
    let mut raw = [0u8; ITIMERVAL_SIZE as usize];
    uaccess::copy_from_user(&mut raw, ptr)
        .map_err(|e| -(e.as_i32() as i64))?;
    let field = |i: usize| i64::from_ne_bytes(raw[i * 8..i * 8 + 8].try_into().expect("8 of 32"));
    let (i_s, i_us, v_s, v_us) = (field(0), field(1), field(2), field(3));
    Ok((timeval_to_ns(i_s, i_us)?, timeval_to_ns(v_s, v_us)?))
}

fn remaining(deadline: u64, now: u64) -> u64 {
    if deadline > now { deadline - now } else { 0 }
}

fn write_itimerval(ptr: u64, interval: u64, value: u64) -> Result<(), i64> {
    validate_user_buf_writable(ptr, ITIMERVAL_SIZE, 1)?;
    let (i_s, i_us) = sched::clock::ns_to_timeval(interval);
    let (v_s, v_us) = sched::clock::ns_to_timeval(value);
    // SAFETY: ptr validated writable for one itimerval; unaligned stores match Linux copy_to_user layout.
    unsafe {
        core::ptr::write_unaligned( ptr       as *mut u64, i_s);
        core::ptr::write_unaligned((ptr +  8) as *mut u64, i_us);
        core::ptr::write_unaligned((ptr + 16) as *mut u64, v_s);
        core::ptr::write_unaligned((ptr + 24) as *mut u64, v_us);
    }
    Ok(())
}

/// `sys_setitimer(which, new, old)` — slot 38.
/// new = `struct itimerval { it_interval: timeval, it_value: timeval }`.
/// # C: O(1)
pub fn sys_setitimer(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let which = args.a0;
    let new = args.a1;
    let old = args.a2;
    if !matches!(which, ITIMER_REAL | ITIMER_VIRTUAL | ITIMER_PROF) { return err(Errno::Einval); }
    let (interval_ns, value_ns) = match read_itimerval(new) { Ok(v) => v, Err(rv) => return rv };
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    if old != 0 {
        let old_pair = match which {
            ITIMER_REAL => {
                let now = now_mono_ns();
                let dl = cur.alarm_ns.load(Ordering::Acquire);
                (cur.alarm_interval_ns.load(Ordering::Acquire), remaining(dl, now))
            }
            ITIMER_VIRTUAL => {
                let now = cur.utime_ns.load(Ordering::Acquire);
                let dl = cur.itimer_virtual_ns.load(Ordering::Acquire);
                (cur.itimer_virtual_interval_ns.load(Ordering::Acquire), remaining(dl, now))
            }
            _ => {
                let now = cur.utime_ns.load(Ordering::Acquire).saturating_add(cur.stime_ns.load(Ordering::Acquire));
                let dl = cur.itimer_prof_ns.load(Ordering::Acquire);
                (cur.itimer_prof_interval_ns.load(Ordering::Acquire), remaining(dl, now))
            }
        };
        if let Err(rv) = write_itimerval(old, old_pair.0, old_pair.1) { return rv; }
    }
    match which {
        ITIMER_REAL => {
            let now = now_mono_ns();
            cur.alarm_interval_ns.store(interval_ns, Ordering::Release);
            cur.alarm_ns.store(if value_ns == 0 { 0 } else { now.saturating_add(value_ns) }, Ordering::Release);
        }
        ITIMER_VIRTUAL => {
            let now = cur.utime_ns.load(Ordering::Acquire);
            cur.itimer_virtual_interval_ns.store(interval_ns, Ordering::Release);
            cur.itimer_virtual_ns.store(if value_ns == 0 { 0 } else { now.saturating_add(value_ns) }, Ordering::Release);
        }
        _ => {
            let now = cur.utime_ns.load(Ordering::Acquire).saturating_add(cur.stime_ns.load(Ordering::Acquire));
            cur.itimer_prof_interval_ns.store(interval_ns, Ordering::Release);
            cur.itimer_prof_ns.store(if value_ns == 0 { 0 } else { now.saturating_add(value_ns) }, Ordering::Release);
        }
    }
    0
}
