// POSIX timers (`timer_create` family). Real impl backed by a
// fixed-size per-task slot array on `Task::posix_timers`. Firing
// happens in the syscall-return tail of the owning task.
//
// Linux UAPI shapes used here:
//   struct timespec   { i64 tv_sec; i64 tv_nsec; }                    16 B
//   struct itimerspec { timespec it_interval; timespec it_value; }    32 B
//   struct sigevent   { union sigval value;          // 8
//                       int   signo;                // 4
//                       int   notify;               // 4
//                       /* notify==SIGEV_THREAD_ID extras ignored */ }
//
// SIGEV_NONE (1) creates a timer that never delivers — useful as a
// pure expirations-counter via `timer_getoverrun`.


use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::PosixTimer;

const SIGEV_SIGNAL:    i32 = 0;
const SIGEV_NONE:      i32 = 1;
const TIMER_ABSTIME:   u64 = 1;

const CLOCK_REALTIME:  u32 = 0;
const CLOCK_MONOTONIC: u32 = 1;

fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

fn read_timespec(p: u64) -> Result<u64, i64> {
    if p == 0 || p >= hal::USER_VA_END
        || p.checked_add(16).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    // SAFETY: p validated < USER_VA_END with 16-byte tail in user range; CPL=0 reads two i64 fields through caller AS at the timespec layout offsets.
    unsafe {
        let sec  = core::ptr::read_volatile(p as *const i64);
        let nsec = core::ptr::read_volatile((p + 8) as *const i64);
        if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 {
            return Err(-(Errno::Einval.as_i32() as i64));
        }
        Ok((sec as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64))
    }
}

fn write_timespec(p: u64, ns: u64) -> Result<(), i64> {
    if p == 0 || p >= hal::USER_VA_END
        || p.checked_add(16).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    let sec = (ns / 1_000_000_000) as i64;
    let nsec = (ns % 1_000_000_000) as i64;
    // SAFETY: p validated < USER_VA_END with 16-byte tail in user range; CPL=0 writes two i64 fields through caller AS at the timespec layout offsets.
    unsafe {
        core::ptr::write_volatile(p as *mut i64, sec);
        core::ptr::write_volatile((p + 8) as *mut i64, nsec);
    }
    Ok(())
}

/// `sys_timer_create(clockid, sigevent, timerid_out)` — slot 222.
/// # C: O(SLOTS)
pub fn sys_timer_create(args: &SyscallArgs) -> i64 {
    let clockid = args.a0 as u32;
    let sigev_p = args.a1;
    let id_out  = args.a2;
    if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC {
        return -(Errno::Einval.as_i32() as i64);
    }
    if id_out == 0 || id_out >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // Default sigevent: SIGEV_SIGNAL with SIGALRM and value=timerid.
    let (signo, value);
    if sigev_p == 0 {
        signo = 14; // SIGALRM
        value = 0;
    } else {
        if sigev_p >= hal::USER_VA_END
            || sigev_p.checked_add(16).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
            return -(Errno::Efault.as_i32() as i64);
        }
        // SAFETY: sigev_p validated < USER_VA_END with 16-byte tail (sigval+signo+notify); CPL=0 reads through caller AS at the sigevent layout offsets.
        let (val, sig, notify) = unsafe {
            let v = core::ptr::read_volatile(sigev_p as *const u64);
            let s = core::ptr::read_volatile((sigev_p + 8)  as *const i32);
            let n = core::ptr::read_volatile((sigev_p + 12) as *const i32);
            (v, s, n)
        };
        if notify == SIGEV_NONE {
            // SIGEV_NONE: no signal delivery, but slot still tracks
            // overruns. Use signo=0xFF as a sentinel "allocated, no fire".
            signo = 0xFF;
            value = val;
        } else if notify == SIGEV_SIGNAL {
            if !(1..=64).contains(&sig) { return -(Errno::Einval.as_i32() as i64); }
            signo = sig;
            value = val;
        } else {
            // SIGEV_THREAD / SIGEV_THREAD_ID — v1 doesn't have userspace
            // notification threads; fall back to SIGEV_SIGNAL semantics.
            if !(1..=64).contains(&sig) { return -(Errno::Einval.as_i32() as i64); }
            signo = sig;
            value = val;
        }
    }
    let cur = match crate::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole writer of posix_timers per `13§5`.
    let slots = unsafe { &mut *cur.posix_timers.get() };
    for i in 0..PosixTimer::SLOTS {
        if slots[i].signo == 0 {
            slots[i] = PosixTimer {
                deadline_ns: 0, interval_ns: 0, sigev_value: value,
                signo, overrun: 0, clockid, _pad: 0,
            };
            // SAFETY: id_out validated above < USER_VA_END; CPL=0 i32 write through caller AS.
            unsafe { core::ptr::write_volatile(id_out as *mut i32, i as i32); }
            return 0;
        }
    }
    -(Errno::Eagain.as_i32() as i64)
}

/// `sys_timer_settime(timerid, flags, new, old)` — slot 223.
/// # C: O(1)
pub fn sys_timer_settime(args: &SyscallArgs) -> i64 {
    let id    = args.a0 as i32;
    let flags = args.a1;
    let new_p = args.a2;
    let old_p = args.a3;
    if !(0..PosixTimer::SLOTS as i32).contains(&id) {
        return -(Errno::Einval.as_i32() as i64);
    }
    if new_p == 0 || new_p >= hal::USER_VA_END
        || new_p.checked_add(32).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return -(Errno::Efault.as_i32() as i64);
    }
    let interval_ns = match read_timespec(new_p)        { Ok(v) => v, Err(rv) => return rv };
    let value_ns    = match read_timespec(new_p + 16)   { Ok(v) => v, Err(rv) => return rv };
    let cur = match crate::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole writer of posix_timers per `13§5`.
    let slots = unsafe { &mut *cur.posix_timers.get() };
    let slot  = &mut slots[id as usize];
    if slot.signo == 0 { return -(Errno::Einval.as_i32() as i64); }
    // Capture old itimerspec for writeback.
    let now = now_ns();
    let old_remaining = if slot.deadline_ns > now { slot.deadline_ns - now } else { 0 };
    let old_interval  = slot.interval_ns;
    let new_deadline  = if value_ns == 0 {
        0  // it_value all-zero ⇒ disarm
    } else if flags & TIMER_ABSTIME != 0 {
        value_ns  // absolute clock value
    } else {
        now.saturating_add(value_ns)
    };
    slot.deadline_ns = new_deadline;
    slot.interval_ns = interval_ns;
    if old_p != 0 {
        let _ = write_timespec(old_p,      old_interval);
        let _ = write_timespec(old_p + 16, old_remaining);
    }
    0
}

/// `sys_timer_gettime(timerid, cur)` — slot 224.
/// # C: O(1)
pub fn sys_timer_gettime(args: &SyscallArgs) -> i64 {
    let id = args.a0 as i32;
    let p  = args.a1;
    if !(0..PosixTimer::SLOTS as i32).contains(&id) {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match crate::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader/writer of posix_timers per `13§5`.
    let slots = unsafe { &*cur.posix_timers.get() };
    let slot  = &slots[id as usize];
    if slot.signo == 0 { return -(Errno::Einval.as_i32() as i64); }
    let now = now_ns();
    let remaining = if slot.deadline_ns > now { slot.deadline_ns - now } else { 0 };
    if let Err(rv) = write_timespec(p,      slot.interval_ns) { return rv; }
    if let Err(rv) = write_timespec(p + 16, remaining)        { return rv; }
    0
}

/// `sys_timer_getoverrun(timerid)` — slot 225. Returns and resets the
/// overrun count for the timer.
/// # C: O(1)
pub fn sys_timer_getoverrun(args: &SyscallArgs) -> i64 {
    let id = args.a0 as i32;
    if !(0..PosixTimer::SLOTS as i32).contains(&id) {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match crate::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole writer of posix_timers per `13§5`.
    let slots = unsafe { &mut *cur.posix_timers.get() };
    let slot  = &mut slots[id as usize];
    if slot.signo == 0 { return -(Errno::Einval.as_i32() as i64); }
    let v = slot.overrun as i64;
    slot.overrun = 0;
    v
}

/// `sys_timer_delete(timerid)` — slot 226.
/// # C: O(1)
pub fn sys_timer_delete(args: &SyscallArgs) -> i64 {
    let id = args.a0 as i32;
    if !(0..PosixTimer::SLOTS as i32).contains(&id) {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match crate::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole writer of posix_timers per `13§5`.
    let slots = unsafe { &mut *cur.posix_timers.get() };
    if slots[id as usize].signo == 0 { return -(Errno::Einval.as_i32() as i64); }
    slots[id as usize] = PosixTimer::default();
    0
}

/// Single-arm dispatch helper for `syscall_glue.rs`. Returns `None`
/// if `nr` is not a timer slot so the caller can fall through.
/// # C: O(1)
pub fn timer_dispatch(nr: u64, args: &SyscallArgs) -> Option<i64> {
    use syscall::nrs::*;
    let rv = match nr {
        NR_TIMER_CREATE     => sys_timer_create(args),
        NR_TIMER_SETTIME    => sys_timer_settime(args),
        NR_TIMER_GETTIME    => sys_timer_gettime(args),
        NR_TIMER_GETOVERRUN => sys_timer_getoverrun(args),
        NR_TIMER_DELETE     => sys_timer_delete(args),
        _ => return None,
    };
    Some(rv)
}

/// Walk the current task's POSIX timer slots; for each armed-and-due
/// timer fire its signal (if any) and advance to the next deadline.
/// Called from the syscall-return tail next to alarm(2) handling.
/// # C: O(SLOTS)
pub fn fire_due_timers() {
    use core::sync::atomic::Ordering;
    let cur = match crate::live::current() { Some(c) => c, None => return };
    let now = now_ns();
    // SAFETY: running task on this CPU; preempt-off; sole writer of posix_timers per `13§5`.
    let slots = unsafe { &mut *cur.posix_timers.get() };
    for slot in slots.iter_mut() {
        if slot.signo == 0 || slot.deadline_ns == 0 { continue; }
        if now < slot.deadline_ns { continue; }
        if slot.signo != 0xFF && (1..=64).contains(&slot.signo) {
            cur.sigpending.fetch_or(1u64 << (slot.signo - 1), Ordering::Release);
        }
        if slot.interval_ns == 0 {
            slot.deadline_ns = 0;
        } else {
            // Advance past now; count overruns for each missed period.
            let mut next = slot.deadline_ns + slot.interval_ns;
            while next <= now {
                slot.overrun = slot.overrun.saturating_add(1);
                next += slot.interval_ns;
            }
            slot.deadline_ns = next;
        }
    }
}
