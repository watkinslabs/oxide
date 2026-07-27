// SIGSTOP / SIGCONT scheduler glue per `28§4` / signal(7).
//
// Self-stop: dispatch tail calls `stop_until_cont` after observing
// a SIGSTOP / default-disposition SIGTSTP / SIGTTIN / SIGTTOU. We
// flip current.state = Stopped + voluntary schedule(); the picker
// won't re-enqueue Stopped tasks. SIGCONT delivery (kill path)
// flips the target back to Runnable + re-enqueues, so the next
// schedule() round picks it up and we resume.

// Arch-neutral now: only uses sched + state primitives that exist on
// both arches. Pre-F16 was gated x86-only by oversight, blocking the
// SIGSTOP / SIGTSTP / SIGTTIN / SIGTTOU default-stop disposition on
// aarch64.

use core::sync::atomic::Ordering;

use crate::exit::notify::{cldstop_notify, Cldstop, ParentSigchld};
use crate::TaskState;

/// Flip current to Stopped + schedule away. Loops until SIGCONT
/// (or any signal flipping state back to Runnable) wakes us.
/// # SAFETY: dispatch tail context — process / kthread, preempt-off,
/// running task is the live one on this CPU.
/// # C: O(N_schedule) until cont
pub fn stop_until_cont() {
    stop_until_cont_sig(crate::Signum::Sigstop as u8)
}

/// Variant of `stop_until_cont` recording the originating stop signal
/// (SIGSTOP=19/SIGTSTP=20/SIGTTIN=21/SIGTTOU=22) for wait4(WUNTRACED).
/// # C: O(N_schedule) until cont
pub fn stop_until_cont_sig(sig: u8) {
    let cur = match crate::live::current() { Some(c) => c, None => return };
    cur.stop_signal.store(sig, Ordering::Release);
    cur.stop_pending.store(true, Ordering::Release);
    cur.set_state(TaskState::Stopped);
    notify_parent_cldstop(cur, Cldstop::Stopped, sig as u32);
    loop {
        // SAFETY: process context, preempt-off, single-CPU; same as voluntary `schedule()` per `13§8`.
        unsafe { crate::live::schedule(); }
        if cur.state() == TaskState::Runnable {
            notify_parent_cldstop(cur, Cldstop::Continued, crate::Signum::Sigcont as u32);
            return;
        }
        // The pick may return us only if no other Runnable task
        // exists (Stopped tasks aren't re-enqueued by schedule).
        // Re-spin: wake_if_stopped on SIGCONT will flip state +
        // re-enqueue; only when that happens do we exit the loop.
        // Defensive: clear any pending SIGSTOP so we don't loop on
        // it forever (Linux wouldn't redeliver SIGSTOP to a Stopped
        // task either).
        cur.sigpending.fetch_and(!(1u64 << 18), Ordering::Release);
    }
}

/// Linux `do_notify_parent_cldstop` (`kernel/signal.c:2290-2346`) wiring for a
/// self-stop / resume. Posts SIGCHLD when the parent's disposition allows it
/// and ALWAYS wakes a `wait4`-blocked parent — a stop that notified nobody left
/// `waitpid(WUNTRACED)` asleep through the stop it was waiting for, which is
/// what made a backgrounded tty read look like a hang rather than a stop.
/// # Ctx: dispatch tail, process context, preempt-off.
/// # C: O(N_waiters)
fn notify_parent_cldstop(cur: &crate::Task, why: Cldstop, status_sig: u32) {
    let Some(parent) = cur.parent() else { return };
    let act = parent.sigactions_ref().get(crate::Signum::Sigchld as u32);
    let n = cldstop_notify(why, ParentSigchld { handler: act.handler, flags: act.flags });
    if n.signal {
        parent.child_sigq_push(crate::task::SigInfo {
            signo: crate::Signum::Sigchld as u32,
            code:  n.si_code,
            pid:   cur.vtgid.load(Ordering::Acquire),
            uid:   cur.creds.ruid.load(Ordering::Acquire),
            value: status_sig as u64,
        });
        parent.sigpending.fetch_or(crate::Signum::Sigchld.bit(), Ordering::Release);
    }
    // wait4 wake BEFORE the signal wake: `wake_wait4_parent` only claims a
    // waiter it observes as `Sleeping`, so a generic signal wake first would
    // leave the WAITERS entry stale (`zombies::claim_wake`).
    if n.wake_parent { crate::live::zombies::wake_wait4_parent(parent.tid); }
    if n.signal { crate::live::signal_wake_up(&parent); }
}
