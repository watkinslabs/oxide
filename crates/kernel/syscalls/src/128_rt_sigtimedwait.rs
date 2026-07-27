// 128 rt_sigtimedwait — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

// A sigtimedwait caller is woken directly by signal delivery through
// `signal_wake_up`; this list supplies the race-free Sleeping publication and
// owns the temporary task reference while it is blocked. Timed waiters also
// use `wakeup_deadline_ns`, which the scheduler's deadline scanner wakes.
static RT_SIGTIMEDWAITERS: sched::live::WaitList = sched::live::WaitList::new();

/// `sys_rt_sigtimedwait(set, info, timeout, sz)` — slot 128.
/// # C: O(1) setup + blocks until signal or timeout
pub fn sys_rt_sigtimedwait(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use hal::TimerOps;
    use syscall::errno::Errno;
    let set     = args.a0;
    let info    = args.a1;
    let timeout = args.a2;
    let sz      = args.a3;
    debug_ssh! {
        klog::write_raw(b"[INFO]  ssh-trace: rt_sigtimedwait set_ptr=");
        klog::write_hex_u64(set);
        klog::write_raw(b" timeout_ptr=");
        klog::write_hex_u64(timeout);
        klog::write_raw(b"\n");
    }
    if sz != 8 { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = validate_user_buf(set, 8, 1) { return rv; }
    if info != 0 {
        if let Err(rv) = validate_user_buf_writable(info, 128, 1) { return rv; }
    }
    if timeout != 0 {
        if let Err(rv) = validate_user_buf(timeout, 16, 1) { return rv; }
    }
    // SAFETY: set validated as a readable 8-byte user sigset_t.
    let wanted = unsafe { core::ptr::read_unaligned(set as *const u64) };
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Eintr.as_i32() as i64),
    };
    let deadline = if timeout != 0 {
        // SAFETY: timeout validated as readable 16-byte timespec storage.
        let secs = unsafe { core::ptr::read_unaligned(timeout as *const i64) };
        // SAFETY: timeout+8 is inside the validated 16-byte timespec.
        let nsec = unsafe { core::ptr::read_unaligned((timeout + 8) as *const i64) };
        // `ktime_set`-clamped decode: a huge-but-valid tv_sec clamps to
        // KTIME_MAX_NS instead of an unbounded relative timeout.
        let total = match ::syscall::time::timespec_to_ns(secs, nsec) {
            Ok(ns) => ns,
            Err(_) => return -(Errno::Einval.as_i32() as i64),
        };
        #[cfg(target_arch = "x86_64")]
        let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
        #[cfg(target_arch = "aarch64")]
        let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
        Some(now.saturating_add(total))
    } else { None };
    loop {
        let pending = cur.sigpending.load(Ordering::Acquire);
        let arrived = pending & wanted;
        if arrived != 0 {
            RT_SIGTIMEDWAITERS.remove_current();
            let sig = arrived.trailing_zeros() + 1;
            let popped: Option<sched::SigInfo> = if sched::signum::is_realtime(sig) {
                let (rec, empty) = cur.rt_pop(sig);
                if empty {
                    cur.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release);
                }
                rec
            } else {
                cur.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release);
                None
            };
            if info != 0 {
                // SAFETY: info validated as writable 128-byte siginfo_t storage.
                unsafe {
                    core::ptr::write_bytes(info as *mut u8, 0, 128);
                    core::ptr::write_unaligned(info as *mut i32, sig as i32);
                    if let Some(rec) = popped {
                        // si_errno=0; si_code at +8; si_pid at +16; si_uid at +20; si_value at +24.
                        core::ptr::write_unaligned((info +  8) as *mut i32, rec.code);
                        core::ptr::write_unaligned((info + 16) as *mut u32, rec.pid);
                        core::ptr::write_unaligned((info + 20) as *mut u32, rec.uid);
                        core::ptr::write_unaligned((info + 24) as *mut u64, rec.value);
                    }
                }
            }
            return sig as i64;
        }
        // Signals outside the waited set still interrupt this syscall when
        // they are deliverable.  In particular, this lets SIGKILL/SIGSTOP
        // escape the wait so the common syscall-exit delivery path can act;
        // leaving such a task Sleeping would make it unkillable.
        if sched::live::sigpend::deliverable_signals_self() & !wanted != 0 {
            RT_SIGTIMEDWAITERS.remove_current();
            return -(Errno::Eintr.as_i32() as i64);
        }
        if let Some(dl) = deadline {
            #[cfg(target_arch = "x86_64")]
            let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
            #[cfg(target_arch = "aarch64")]
            let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
            if now >= dl {
                RT_SIGTIMEDWAITERS.remove_current();
                return -(Errno::Eagain.as_i32() as i64);
            }
        }
        // Publish Sleeping before yielding. A concurrent signal sender either
        // sees this state and enqueues us, or wins just before this point; the
        // post-park recheck below handles the latter without a lost wake.
        // SAFETY: process context; the loop immediately hands control to the
        // scheduler unless the post-publication recheck observes a signal.
        unsafe { RT_SIGTIMEDWAITERS.park_with_deadline(deadline.unwrap_or(0)); }
        if cur.sigpending.load(Ordering::Acquire) & wanted != 0
            || sched::live::sigpend::deliverable_signals_self() & !wanted != 0
        {
            RT_SIGTIMEDWAITERS.cancel_current_park();
            continue;
        }
        // SAFETY: the task is Sleeping on the published wait list; signal
        // delivery or the deadline scanner transitions it back to Runnable.
        unsafe { sched::live::park_yield(); }
    }
}
