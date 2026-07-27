// 128 rt_sigtimedwait — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::signal_common::{SIGSET_BYTES, SIGINFO_BYTES, write_user_siginfo};
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

// A sigtimedwait caller is woken directly by signal delivery through
// `signal_wake_up`; this list supplies the race-free Sleeping publication and
// owns the temporary task reference while it is blocked. Timed waiters also
// use `wakeup_deadline_ns`, which the scheduler's deadline scanner wakes.
static RT_SIGTIMEDWAITERS: sched::live::WaitList = sched::live::WaitList::new();

/// `struct timespec` — two `__kernel_time64_t`, 16 bytes on both arches.
const TIMESPEC_BYTES: u64 = 2 * core::mem::size_of::<i64>() as u64;
/// Byte offset of `tv_nsec` within `struct timespec`.
const TV_NSEC_OFF: u64 = core::mem::size_of::<i64>() as u64;

/// `sys_rt_sigtimedwait(set, info, timeout, sigsetsize)` — slot 128.
///
/// Linux `SYSCALL_DEFINE4(rt_sigtimedwait)` → `do_sigtimedwait`:
///   1. `sigsetsize != sizeof(sigset_t)` → EINVAL (an exact match here, unlike
///      `rt_sigpending`'s `>`).
///   2. copy the set → EFAULT; copy the timespec → EFAULT. `uinfo` is NOT
///      probed up front — a bad `info` pointer must not pre-empt EAGAIN.
///   3. `timespec64_valid` → EINVAL (negative `tv_sec`, out-of-range
///      `tv_nsec`); the value is `ktime_set`-clamped so a huge `tv_sec` cannot
///      install an unreachable deadline.
///   4. SIGKILL/SIGSTOP are removed from the waited set — they can never be
///      waited FOR, only acted on.
///   5. Dequeue from the thread-private set, then the process-directed one.
///      The signal is CONSUMED, not merely observed.
///   6. A zero timeout polls: Linux's `if (!sig && timeout)` skips the sleep
///      entirely, so the answer is EAGAIN even when other signals are
///      deliverable.
///   7. Otherwise sleep; EAGAIN on expiry, EINTR when a signal OUTSIDE the set
///      interrupts (a signal inside the set is the success case, never EINTR).
///   8. `copy_siginfo_to_user` only after a successful dequeue → EFAULT.
/// # C: O(1) setup + blocks until signal or timeout
pub fn sys_rt_sigtimedwait(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    use syscall::errno::Errno;
    use sched::live::sigpend::Signum;
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
    if syscall::sigset::check_exact(sz).is_err() { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = validate_user_buf(set, SIGSET_BYTES, 1) { return rv; }
    if timeout != 0 {
        if let Err(rv) = validate_user_buf(timeout, TIMESPEC_BYTES, 1) { return rv; }
    }
    // SAFETY: set validated as a readable 8-byte user sigset_t.
    let requested = unsafe { core::ptr::read_unaligned(set as *const u64) };
    // Linux `sigdelsetmask(&mask, sigmask(SIGKILL)|sigmask(SIGSTOP))`: a waiter
    // must never swallow a fatal signal, or the task becomes unkillable.
    let wanted = requested & !(Signum::Sigkill.bit() | Signum::Sigstop.bit());
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Eintr.as_i32() as i64),
    };
    // `Some(0)` is Linux's poll (`timeout` falsy ⇒ never sleep); `None` is a
    // NULL timespec, which waits forever.
    let total = if timeout != 0 {
        // SAFETY: timeout validated as readable 16-byte timespec storage.
        let secs = unsafe { core::ptr::read_unaligned(timeout as *const i64) };
        // SAFETY: timeout+8 is inside the validated 16-byte timespec.
        let nsec = unsafe { core::ptr::read_unaligned((timeout + TV_NSEC_OFF) as *const i64) };
        // `timespec64_valid` + the `ktime_set` clamp in one: rejects a negative
        // tv_sec or an out-of-range tv_nsec, and caps a huge-but-valid tv_sec
        // at KTIME_MAX_NS instead of installing an unbounded deadline.
        match ::syscall::time::timespec_to_ns(secs, nsec) {
            Ok(ns) => Some(ns),
            Err(_) => return -(Errno::Einval.as_i32() as i64),
        }
    } else { None };
    #[cfg(target_arch = "x86_64")]
    let start = hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let start = hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let deadline = total.filter(|t| *t != 0).map(|t| start.saturating_add(t));
    let poll_only = total == Some(0);
    loop {
        if let Some((sig, rec)) = dequeue_wanted(&cur, wanted) {
            RT_SIGTIMEDWAITERS.remove_current();
            if let Err(rv) = emit_siginfo(info, sig, rec) { return rv; }
            return sig as i64;
        }
        // Linux never sleeps for a zero timeout, so EAGAIN wins over the "some
        // other signal is pending" EINTR the sleeping path would produce.
        if poll_only {
            RT_SIGTIMEDWAITERS.remove_current();
            return -(Errno::Eagain.as_i32() as i64);
        }
        // Signals outside the waited set still interrupt this syscall when
        // they are deliverable. In particular, this lets SIGKILL/SIGSTOP
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
        // Publish Sleeping BEFORE the post-park recheck. A concurrent sender
        // either sees this state and enqueues us, or wins just before this
        // point — and then the recheck below catches it. Doing the two in the
        // other order is the classic check-then-park lost wakeup.
        // SAFETY: process context; the loop immediately hands control to the
        // scheduler unless the post-publication recheck observes a signal.
        unsafe { RT_SIGTIMEDWAITERS.park_with_deadline(deadline.unwrap_or(0)); }
        if sched::live::sigpend::all_pending(&cur) & wanted != 0
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

/// Linux `dequeue_signal(&mask, ...)` restricted to `wanted`: claim the
/// lowest-numbered pending signal in the set from the thread-private queue,
/// then from the process-directed one. `None` when nothing in the set is
/// pending, or when a concurrent consumer won the claim (caller re-loops).
/// # C: O(1)
fn dequeue_wanted(cur: &sched::Task, wanted: u64) -> Option<(u32, Option<sched::SigInfo>)> {
    let arrived = sched::live::sigpend::all_pending(cur) & wanted;
    if arrived == 0 { return None; }
    let sig = arrived.trailing_zeros() + 1;
    sched::live::sigpend::dequeue_signal(cur, sig).map(|rec| (sig, rec))
}

/// `copy_siginfo_to_user` for a successfully dequeued signal. Validated HERE
/// rather than at syscall entry: Linux reports a bad `uinfo` as EFAULT only
/// after the signal is consumed, so an unusable pointer never turns a timeout
/// into anything but EAGAIN.
/// # C: O(1)
fn emit_siginfo(info: u64, sig: u32, rec: Option<sched::SigInfo>) -> Result<(), i64> {
    if info == 0 { return Ok(()); }
    validate_user_buf_writable(info, SIGINFO_BYTES, 1)?;
    write_user_siginfo(info, sig, rec);
    Ok(())
}
