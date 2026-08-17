// Linux `___wait_event` and
// `prepare_to_wait_event` — the ONE
// interruptible-sleep loop every blocking path is built from.
//
// Why this exists: `prepare_to_wait_event` returns `-ERESTARTSYS`
// when `signal_pending_state()` holds, and `___wait_event`
// propagates it. So in Linux `-ERESTARTSYS` is the DEFAULT
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

use core::panic::Location;

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
#[track_caller]
pub unsafe fn wait_event(wq: &WaitList, state: WaitState, deadline_ns: u64,
                         now: impl Fn() -> u64, cond: impl FnMut() -> bool) -> WaitOutcome {
    // SAFETY: forwards this function's contract to the shared loop unchanged;
    // only the recorded wait site is added.
    unsafe { wait_event_at(Location::caller(), wq, state, deadline_ns, now, cond) }
}

/// [`wait_event`] with the wait site supplied by the caller, so a named wrapper
/// records the SUBSYSTEM's line rather than its own. # SAFETY: see [`wait_event`].
/// # C: O(N_wakeups) condition evaluations
unsafe fn wait_event_at(site: &'static Location<'static>, wq: &WaitList, state: WaitState,
                        deadline_ns: u64, now: impl Fn() -> u64,
                        mut cond: impl FnMut() -> bool) -> WaitOutcome {
    let timed = deadline_ns != 0;
    // The public wait macros test before creating a waiter. Besides avoiding
    // needless state churn on the ready fast path, this keeps a current task
    // out of a self-wake/deferred-placement round when no sleep is required.
    if cond() { return WaitOutcome::Ready; }
    crate::park_site::note(site);
    loop {
        // Publish Sleeping and enqueue before either condition or signal
        // recheck. A producer racing either check can therefore find and wake
        // this waiter instead of losing the event.
        // SAFETY: forwarded fn-level contract — process context, runqueue
        // installed, no waker-held lock owned by this caller.
        unsafe { wq.park_with_wait_state(deadline_ns, state); }
        if cond() { break; }
        if signal_pending_state_current(state) {
            // Dequeue, THEN report the restart, so an
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
#[track_caller]
pub unsafe fn wait_event_interruptible(wq: &WaitList, cond: impl FnMut() -> bool) -> WaitOutcome {
    // SAFETY: forwarded contract; untimed, so the clock is never consulted.
    unsafe { wait_event_at(Location::caller(), wq, WaitState::Interruptible, 0, || 0, cond) }
}

/// Linux `wait_event(wq, cond)` for a wait which deliberately ignores signals.
///
/// # SAFETY: process context on the running task's own CPU, with the runqueue
/// installed; the caller must hold no lock that a waker of `wq` also takes.
/// # C: O(N_wakeups) condition evaluations
#[track_caller]
pub unsafe fn wait_event_uninterruptible(wq: &WaitList, mut cond: impl FnMut() -> bool) -> WaitOutcome {
    // Linux's public wait_event macro tests before publishing a waiter. This
    // avoids a needless task-state transition when the predicate is already
    // true; the loop below still publishes before every sleeping recheck.
    if cond() { return WaitOutcome::Ready; }
    crate::park_site::note(Location::caller());
    loop {
        // SAFETY: forwarded fn-level contract; plain publication intentionally
        // ignores signals, matching an uninterruptible worker/completion wait.
        unsafe { wq.park(); }
        if cond() { break; }
        // SAFETY: publication above makes a subsequent schedule race-free.
        unsafe { super::park_yield(); }
        if cond() { break; }
    }
    wq.cancel_current_park();
    WaitOutcome::Ready
}

/// Uninterruptible predicate wait with a caller-owned action between waiter
/// publication and the condition recheck.
///
/// This is Linux's `prepare_to_wait()` shape for protocols whose wake-enable
/// flag must be published only after the task is visible on the wait queue
/// (SQPOLL's `IORING_SQ_NEED_WAKEUP` handshake is one).  `prepare` must be
/// idempotent: it can run again after a spurious wake before the predicate
/// becomes true.  It must not take a lock that a waker holds.
///
/// # SAFETY: process context on the running task's CPU with a live runqueue;
/// `prepare` and the predicate together must provide the condition's normal
/// publication/recheck contract.
/// # C: O(N_wakeups) condition evaluations
#[track_caller]
pub unsafe fn wait_event_uninterruptible_prepare(wq: &WaitList,
                                                 mut prepare: impl FnMut(),
                                                 mut cond: impl FnMut() -> bool) -> WaitOutcome {
    crate::park_site::note(Location::caller());
    loop {
        // SAFETY: forwarded function contract; publish before enabling the
        // producer's wake doorbell, exactly as Linux's prepare_to_wait loop.
        unsafe { wq.park(); }
        prepare();
        if cond() { break; }
        // SAFETY: publication above makes the schedule race-free.
        unsafe { super::park_yield(); }
        if cond() { break; }
    }
    wq.cancel_current_park();
    WaitOutcome::Ready
}

/// Timed uninterruptible predicate wait. `deadline_ns == 0` disables timeout.
/// # SAFETY: see [`wait_event_uninterruptible`].
/// # C: O(N_wakeups)
#[track_caller]
pub unsafe fn wait_event_uninterruptible_until(wq: &WaitList, deadline_ns: u64,
                                               now: impl Fn() -> u64,
                                               cond: impl FnMut() -> bool) -> WaitOutcome {
    // SAFETY: forwards this function's contract to the shared timed loop.
    unsafe { wait_event_uninterruptible_until_at(Location::caller(), wq, deadline_ns, now, cond) }
}

/// [`wait_event_uninterruptible_until`] with a caller-supplied wait site.
/// # SAFETY: see [`wait_event_uninterruptible_until`].
/// # C: O(N_wakeups)
unsafe fn wait_event_uninterruptible_until_at(site: &'static Location<'static>, wq: &WaitList,
                                              deadline_ns: u64, now: impl Fn() -> u64,
                                              mut cond: impl FnMut() -> bool) -> WaitOutcome {
    let timed = deadline_ns != 0;
    if cond() { return WaitOutcome::Ready; }
    crate::park_site::note(site);
    loop {
        // SAFETY: forwarded sleepable-context contract; this is the timed
        // prepared publication owned by the shared predicate-wait loop.
        unsafe { wq.park_with_deadline(deadline_ns); }
        if cond() { break; }
        if timed && now() >= deadline_ns {
            wq.cancel_current_park();
            return if cond() { WaitOutcome::Ready } else { WaitOutcome::TimedOut };
        }
        // SAFETY: waiter publication above makes the schedule race-free.
        unsafe { super::park_yield(); }
        if cond() { break; }
        // A deadline wake resumes here after park_yield.  Test it before the
        // next publication: otherwise an expired wait is immediately armed
        // again and can never report its timeout to the caller.
        if timed && now() >= deadline_ns {
            wq.cancel_current_park();
            return if cond() { WaitOutcome::Ready } else { WaitOutcome::TimedOut };
        }
    }
    wq.cancel_current_park();
    WaitOutcome::Ready
}

/// Sleep once until an absolute monotonic deadline.
///
/// This is the scheduler-owned counterpart of an uninterruptible timeout:
/// hardware polling re-reads its condition after this returns, while
/// producer-backed conditions use the predicate wait above.
///
/// # SAFETY: process context on a running task with no lock held that can
/// block the scheduler or deadline wakeup path.
/// # Ctx: process
/// # Sleeps: yes
/// # C: O(1) plus scheduler wakeup
#[track_caller]
pub unsafe fn sleep_uninterruptible_until(deadline_ns: u64, now: impl Fn() -> u64) {
    let wait = WaitList::new();
    // SAFETY: the local wait list lives through its sole deadline wait; the
    // caller satisfies the shared timed-wait process-context contract.
    let _ = unsafe {
        wait_event_uninterruptible_until_at(Location::caller(), &wait, deadline_ns, now, || false)
    };
}

/// Linux `wait_event_interruptible_timeout(wq, cond, timeout)`, on an ABSOLUTE
/// monotonic deadline rather than a relative jiffy count so a restarted wait
/// resumes the REMAINDER (`13§8`).
/// # SAFETY: see [`wait_event`].
/// # C: O(N_wakeups)
#[track_caller]
pub unsafe fn wait_event_interruptible_until(wq: &WaitList, deadline_ns: u64,
                                             now: impl Fn() -> u64,
                                             cond: impl FnMut() -> bool) -> WaitOutcome {
    // SAFETY: this fn is itself `unsafe` and forwards `wait_event`'s contract
    // unchanged — sleepable context, `wq` outliving the wait.
    unsafe { wait_event_at(Location::caller(), wq, WaitState::Interruptible, deadline_ns, now, cond) }
}

/// Linux `wait_event_killable(wq, cond)` — only a fatal signal ends the wait.
/// # SAFETY: see [`wait_event`].
/// # C: O(N_wakeups)
#[track_caller]
pub unsafe fn wait_event_killable(wq: &WaitList, cond: impl FnMut() -> bool) -> WaitOutcome {
    // SAFETY: forwarded contract; untimed, so the clock is never consulted.
    unsafe { wait_event_at(Location::caller(), wq, WaitState::Killable, 0, || 0, cond) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    /// A predicate that is false on its first evaluation and true afterwards,
    /// so the wait reaches its publication (and therefore records a site) and
    /// still terminates in the host build, which installs no runqueue.
    fn false_then_true(calls: &AtomicU32) -> impl FnMut() -> bool + '_ {
        move || calls.fetch_add(1, Ordering::Relaxed) != 0
    }

    #[test]
    fn a_killable_wait_records_its_callers_line_not_wait_events() {
        let wait = WaitList::new();
        let calls = AtomicU32::new(0);
        let here = line!() + 2;
        let out = unsafe {
            wait_event_killable(&wait, false_then_true(&calls))
        };
        assert_eq!(out, WaitOutcome::Ready);
        let site = crate::park_site::last_note().expect("wait must record a site");
        assert!(site.file().ends_with("wait_event.rs"));
        assert_eq!(site.line(), here, "the recorded site must be the CALLER's line");
    }

    #[test]
    fn every_public_wait_family_records_its_callers_line() {
        let wait = WaitList::new();
        let observed = [
            {
                let c = AtomicU32::new(0);
                let at = line!() + 2;
                let out = unsafe {
                    wait_event_interruptible(&wait, false_then_true(&c))
                };
                ("interruptible", at, out, crate::park_site::last_note())
            },
            {
                let c = AtomicU32::new(0);
                let at = line!() + 2;
                let out = unsafe {
                    wait_event_uninterruptible(&wait, false_then_true(&c))
                };
                ("uninterruptible", at, out, crate::park_site::last_note())
            },
            {
                let c = AtomicU32::new(0);
                let at = line!() + 2;
                let out = unsafe {
                    wait_event_uninterruptible_until(&wait, 0, || 0, false_then_true(&c))
                };
                ("uninterruptible_until", at, out, crate::park_site::last_note())
            },
            {
                let c = AtomicU32::new(0);
                let at = line!() + 2;
                let out = unsafe {
                    wait_event(&wait, WaitState::Interruptible, 0, || 0, false_then_true(&c))
                };
                ("wait_event", at, out, crate::park_site::last_note())
            },
        ];
        for (name, at, out, site) in observed {
            assert_eq!(out, WaitOutcome::Ready, "{name}");
            let site = site.expect("every family must record a site");
            assert_eq!(site.line(), at, "{name} recorded the wrong line");
        }
    }

    #[test]
    fn prepared_predicate_arms_before_its_first_recheck() {
        let wait = WaitList::new();
        let armed = AtomicBool::new(false);
        let prepares = AtomicU32::new(0);
        // Hosted tests have no installed runqueue, but the helper still runs
        // its publication/prepare/recheck sequencing synchronously.
        // SAFETY: hosted test in process context holding no lock a waker takes; with
        // no runqueue installed the helper runs its prepare/recheck sequence inline.
        let out = unsafe {
            wait_event_uninterruptible_prepare(
                &wait,
                || {
                    prepares.fetch_add(1, Ordering::Relaxed);
                    armed.store(true, Ordering::Release);
                },
                || armed.load(Ordering::Acquire),
            )
        };
        assert_eq!(out, WaitOutcome::Ready);
        assert_eq!(prepares.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn uninterruptible_ready_predicate_never_publishes_a_waiter() {
        let wait = WaitList::new();
        let checks = AtomicU32::new(0);
        // SAFETY: hosted test in process context; the ready predicate short-circuits
        // before any waiter is published, so no runqueue is required.
        let out = unsafe {
            wait_event_uninterruptible(&wait, || {
                checks.fetch_add(1, Ordering::Relaxed);
                true
            })
        };
        assert_eq!(out, WaitOutcome::Ready);
        assert_eq!(checks.load(Ordering::Relaxed), 1);
        assert!(!wait.has_waiters());
    }

    #[test]
    fn timed_uninterruptible_ready_predicate_never_reads_the_clock() {
        let wait = WaitList::new();
        let clock_reads = AtomicU32::new(0);
        // SAFETY: hosted test in process context; the predicate is immediately true so
        // the helper returns before publishing a waiter or consulting the clock.
        let out = unsafe {
            wait_event_uninterruptible_until(&wait, 1, || {
                clock_reads.fetch_add(1, Ordering::Relaxed);
                0
            }, || true)
        };
        assert_eq!(out, WaitOutcome::Ready);
        assert_eq!(clock_reads.load(Ordering::Relaxed), 0);
        assert!(!wait.has_waiters());
    }

    #[test]
    fn deadline_sleep_uses_the_existing_timed_wait_owner() {
        let reads = AtomicU32::new(0);
        // Hosted has no current task, so the timed wait performs its terminal
        // deadline recheck synchronously instead of trying to schedule.
        // SAFETY: hosted test — no current task, so the timed wait takes its terminal
        // synchronous recheck path and never schedules or touches a runqueue.
        unsafe {
            sleep_uninterruptible_until(7, || {
                reads.fetch_add(1, Ordering::Relaxed);
                7
            });
        }
        assert_eq!(reads.load(Ordering::Relaxed), 1);
    }
}
