// 130 rt_sigsuspend — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::signal_common::SIGSET_BYTES;
use crate::userbuf::validate_user_buf;

// A suspended task is woken by `signal_wake_up` exactly like an
// `rt_sigtimedwait` caller; this list gives it the race-free Sleeping
// publication and owns its task reference while it is blocked. Linux's
// `while (!signal_pending(current)) { TASK_INTERRUPTIBLE; schedule(); }` —
// NOT a yield-spin, which burns a CPU for the whole suspension.
static SIGSUSPENDERS: sched::live::WaitList = sched::live::WaitList::new();

/// `sys_rt_sigsuspend(mask, sigsetsize)` — slot 130.
///
/// Linux `SYSCALL_DEFINE2(rt_sigsuspend)` → `sigsuspend`:
///   1. `sigsetsize != sizeof(sigset_t)` → EINVAL.
///   2. copy the mask → EFAULT.
///   3. `saved_sigmask = blocked; set_current_blocked(new); set_restore_sigmask()`.
///      The old mask is NOT put back here. A handler that fires on the way out
///      must run under the TEMPORARY mask, and `rt_sigreturn` restores the
///      saved one from the signal frame; the syscall-return tail restores it
///      directly when no handler runs. Restoring eagerly before returning
///      reopens the very race `sigsuspend(2)` exists to close — the handler
///      would run with the caller's original mask.
///   4. Sleep until a signal is deliverable.
///   5. ALWAYS `-ERESTARTNOHAND` (`kernel/signal.c:4853`). There is no success
///      return. With a delivered handler the tail reports EINTR; with none it
///      restarts the suspend.
/// # C: O(1) setup + blocks until a deliverable signal
pub fn sys_rt_sigsuspend(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    use sched::live::sigpend::Signum;
    let mask = args.a0;
    let sz   = args.a1;
    if syscall::sigset::check_exact(sz).is_err() { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = validate_user_buf(mask, SIGSET_BYTES, 1) { return rv; }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Eintr.as_i32() as i64),
    };
    // SAFETY: mask validated as a readable 8-byte user sigset_t.
    let m = unsafe { core::ptr::read_unaligned(mask as *const u64) };
    // signal(7): SIGKILL/SIGSTOP are never blockable, so suspending under a
    // mask that names them must not make the task unkillable.
    let new_mask = m & !(Signum::Sigkill.bit() | Signum::Sigstop.bit());
    cur.arm_saved_sigmask(new_mask);
    loop {
        // Linux `signal_pending(current)`: any signal the return path will
        // actually act on. Default-ignored dispositions are excluded because
        // Linux drops those at SEND time (`sig_ignored`), so they never wake a
        // suspended task there either.
        if sched::live::sigpend::deliverable_signals_self() != 0 {
            SIGSUSPENDERS.remove_current();
            // Linux `sigsuspend` (`kernel/signal.c:4843-4854`) ends with
            // `set_restore_sigmask(); return -ERESTARTNOHAND;`. The doc above
            // already said so while this returned a flat EINTR, which drops
            // the restart Linux performs when no handler frame was built — the
            // suspend should resume rather than report a spurious EINTR.
            return syscall::restart::restart_nohand();
        }
        // Publish Sleeping BEFORE the recheck: a sender that wins the gap is
        // caught below instead of being lost (check-then-park).
        // SAFETY: process context; control goes to the scheduler immediately
        // unless the post-publication recheck observes a deliverable signal.
        unsafe { SIGSUSPENDERS.park_with_deadline(0); }
        if sched::live::sigpend::deliverable_signals_self() != 0 {
            SIGSUSPENDERS.cancel_current_park();
            continue;
        }
        // SAFETY: the task is Sleeping on the published wait list; signal
        // delivery (`signal_wake_up`) transitions it back to Runnable.
        unsafe { sched::live::park_yield(); }
    }
}
