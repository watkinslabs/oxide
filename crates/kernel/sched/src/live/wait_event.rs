// Linux `___wait_event` (`include/linux/wait.h:302-327`) and
// `prepare_to_wait_event` (`kernel/sched/wait.c:289-320`) — the ONE
// interruptible-sleep loop every blocking path is built from.
//
// Why this exists: `prepare_to_wait_event` returns `-ERESTARTSYS`
// (`wait.c:309`) when `signal_pending_state()` holds, and `___wait_event`
// propagates it (`wait.h:315-318`). So in Linux `-ERESTARTSYS` is the DEFAULT
// outcome of an interrupted wait and a real `-EINTR` is the exception a
// syscall opts into. This kernel had no such primitive: 46 hand-rolled loops
// each re-derived enqueue / signal-check / recheck / park, and every one of
// them returned `-EINTR`, losing the restart Linux performs whenever no user
// handler frame was built. One owner, one rule.
//
// The loop shape is Linux's, in order, and the order is the contract:
//   prepare (publish Sleeping + enqueue, THEN test the signal)
//   -> condition -> interrupted-exit -> park -> recondition -> finish
// Testing the condition after enqueueing is what closes the lost-wakeup race;
// testing the signal after publishing Sleeping is what closes the
// signal-before-sleep race (`WaitList::park_interruptible_with_deadline`).
//
// `sched` carries no HAL clock (the deadline scanner is fed `now_ns` by its
// caller, `tick_wake_expired`), so the timed variant takes the clock as a
// closure rather than reaching for `hal_*` and inverting the dependency.

use crate::task::{WaitOutcome, WaitState, signal_pending_state};
use super::wait_list::WaitList;

/// [`signal_pending_state`] for the running task. `false` when no task is
/// current (boot paths with no runqueue).
/// # C: O(N_sig)
fn signal_pending_state_current(state: WaitState) -> bool {
    super::schedule::current().map(|t| signal_pending_state(t, state)).unwrap_or(false)
}

/// Linux `___wait_event`'s loop, with the clock supplied by the caller.
///
/// `cond` is re-evaluated exactly where `___wait_event` re-evaluates it: after
/// the enqueue and again after the park. `deadline_ns == 0` means "no timeout"
/// (Linux's plain `schedule()` arm) and `now` is then never called; otherwise
/// `deadline_ns` is an ABSOLUTE monotonic deadline whose expiry reports
/// [`WaitOutcome::TimedOut`].
///
/// Callers map [`WaitOutcome::Interrupted`] to their subsystem error's
/// `Erestartsys`, never to `Eintr`.
///
/// # SAFETY: process context on the running task's own CPU, with the runqueue
/// installed; the caller must hold no lock that a waker of `wq` also takes.
/// # Ctx: process
/// # Sleeps: yes
/// # C: O(N_wakeups) condition evaluations
pub unsafe fn wait_event(wq: &WaitList, state: WaitState, deadline_ns: u64,
                         now: impl Fn() -> u64, mut cond: impl FnMut() -> bool) -> WaitOutcome {
    let timed = deadline_ns != 0;
    loop {
        // `prepare_to_wait_event`: publish Sleeping and enqueue, THEN test the
        // signal. This order is what makes the post-park recheck sound — a
        // waker firing in the gap finds us already queued.
        // SAFETY: forwarded fn-level contract — process context, runqueue
        // installed, no waker-held lock owned by this caller.
        unsafe { wq.park_interruptible_with_deadline(deadline_ns); }
        if cond() { break; }
        if signal_pending_state_current(state) {
            // `wait.c:308-309`: dequeue, THEN report the restart, so an
            // exclusive waiter that bails cannot swallow another's wakeup.
            wq.cancel_current_park();
            return WaitOutcome::Interrupted;
        }
        if timed && now() >= deadline_ns {
            wq.cancel_current_park();
            // Linux rechecks once more after `schedule_timeout` returns 0: a
            // condition that became true in the same instant is a success,
            // not a timeout.
            return if cond() { WaitOutcome::Ready } else { WaitOutcome::TimedOut };
        }
        // SAFETY: the task published Sleeping above; a waker, a signal or the
        // deadline scanner rouses it and the loop re-tests every exit.
        unsafe { super::park_yield(); }
        if cond() { break; }
    }
    // `finish_wait`: drop any surviving registration and return Runnable.
    wq.cancel_current_park();
    WaitOutcome::Ready
}

/// Linux `wait_event_interruptible(wq, cond)`.
/// # SAFETY: see [`wait_event`].
/// # C: O(N_wakeups)
pub unsafe fn wait_event_interruptible(wq: &WaitList, cond: impl FnMut() -> bool) -> WaitOutcome {
    // SAFETY: forwarded contract; untimed, so the clock is never consulted.
    unsafe { wait_event(wq, WaitState::Interruptible, 0, || 0, cond) }
}

/// Linux `wait_event_interruptible_timeout(wq, cond, timeout)`, on an ABSOLUTE
/// monotonic deadline rather than a relative jiffy count so a restarted wait
/// resumes the REMAINDER (`13§8`).
/// # SAFETY: see [`wait_event`].
/// # C: O(N_wakeups)
pub unsafe fn wait_event_interruptible_until(wq: &WaitList, deadline_ns: u64,
                                             now: impl Fn() -> u64,
                                             cond: impl FnMut() -> bool) -> WaitOutcome {
    // SAFETY: forwarded contract.
    unsafe { wait_event(wq, WaitState::Interruptible, deadline_ns, now, cond) }
}

/// Linux `wait_event_killable(wq, cond)` — only a fatal signal ends the wait.
/// # SAFETY: see [`wait_event`].
/// # C: O(N_wakeups)
pub unsafe fn wait_event_killable(wq: &WaitList, cond: impl FnMut() -> bool) -> WaitOutcome {
    // SAFETY: forwarded contract; untimed, so the clock is never consulted.
    unsafe { wait_event(wq, WaitState::Killable, 0, || 0, cond) }
}
