// SIGSTOP / SIGCONT scheduler glue per `28§4` / signal(7).
//
// Self-stop: dispatch tail calls `stop_until_cont` after observing
// a SIGSTOP / default-disposition SIGTSTP / SIGTTIN / SIGTTOU. We
// flip current.state = Stopped + voluntary schedule(); the picker
// won't re-enqueue Stopped tasks. SIGCONT delivery (kill path)
// flips the target back to Runnable + re-enqueues, so the next
// schedule() round picks it up and we resume.

#![cfg(target_os = "oxide-kernel")]
#![cfg(target_arch = "x86_64")]

use core::sync::atomic::Ordering;

use sched::TaskState;

/// Flip current to Stopped + schedule away. Loops until SIGCONT
/// (or any signal flipping state back to Runnable) wakes us.
/// # SAFETY: dispatch tail context — process / kthread, preempt-off,
/// running task is the live one on this CPU.
/// # C: O(N_schedule) until cont
pub fn stop_until_cont() {
    let cur = match crate::sched::current() { Some(c) => c, None => return };
    cur.set_state(TaskState::Stopped);
    loop {
        // SAFETY: process context, preempt-off, single-CPU; same as voluntary `schedule()` per `13§8`.
        unsafe { crate::sched::schedule(); }
        if cur.state() == TaskState::Runnable { return; }
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
