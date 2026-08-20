// Which signal-wake class each blocking family publishes its sleep as.
//
// The state a sleeper publishes is not a detail of the wait list — it is the
// whole of whether a signal can ever reach that sleeper.
// `signal_wake_up` consults `signal_pending_state(task, task.sleep_wait_state())`
// and `signal_pending_state` returns false outright for an uninterruptible
// wait, so a family that publishes the wrong class is UNSIGNALLABLE: SIGKILL
// included, with no diagnostic and nothing to wake it but its own event.
//
// Measured: poll/select/ppoll/pselect and epoll all published
// `Uninterruptible`, and the defect was invisible because those waits are
// normally ended by fd readiness or a timeout. The one shape with neither is
// `ppoll(NULL, 0, NULL, NULL)` — which is what glibc compiles `pause()` into
// on aarch64, there being no `pause` syscall on that architecture. systemd's
// `(sd-mkuserns)` helper calls `freeze()`, its parent SIGKILLs it and waits;
// on aarch64 the SIGKILL could not land, the parent's `waitid` never returned,
// and `systemd-journald.service` timed out at 45 s and never started. On
// x86_64 the identical userspace takes `sys_pause` and lives.
//
// The reference sleeps every member of this family in `TASK_INTERRUPTIBLE`.

use crate::task::WaitState;

/// poll(2), ppoll(2), select(2), pselect6(2) and epoll_wait(2).
///
/// Named here rather than spelled at each park site so the choice is one
/// decision with one test, and so it is checkable without a kernel — the
/// wait-list code that consumes it is compiled only into the kernel target.
/// # C: O(1)
pub const fn poll_family() -> WaitState { WaitState::Interruptible }

/// An event-driven kernel worker while its work queue is empty.
///
/// Ordinary idle time is not an uninterruptible resource wait and therefore
/// must not enter the hung-task candidate set. # C: O(1)
pub const fn event_worker() -> WaitState { WaitState::Interruptible }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::signal_pending_state;
    use crate::{SchedClass, Signum, Task};
    use core::sync::atomic::Ordering;

    fn sleeper(tid: u32, sig: Signum) -> Task {
        let t = Task::new(tid, "sleeper", SchedClass::Normal { weight: 1024 });
        t.sigpending.fetch_or(sig.bit(), Ordering::Release);
        t
    }

    /// The property the whole module exists for: a task parked by this family
    /// with a pending SIGKILL must be one `signal_wake_up` can claim.
    #[test]
    fn a_poll_family_sleeper_can_be_reached_by_a_fatal_signal() {
        let t = sleeper(7001, Signum::Sigkill);
        assert!(signal_pending_state(&t, poll_family()),
            "a poll/ppoll/epoll sleeper must be wakeable by SIGKILL");
    }

    /// ...and by an ordinary deliverable signal, which is what makes `ppoll`
    /// return EINTR rather than sleeping through the handler.
    #[test]
    fn a_poll_family_sleeper_is_interrupted_by_an_ordinary_signal() {
        let t = sleeper(7002, Signum::Sigusr1);
        assert!(signal_pending_state(&t, poll_family()));
    }

    /// The control: the class it used to publish reaches neither.
    #[test]
    fn an_uninterruptible_sleeper_reaches_neither_and_is_why_this_exists() {
        let t = sleeper(7003, Signum::Sigkill);
        assert!(!signal_pending_state(&t, WaitState::Uninterruptible));
        assert_ne!(poll_family(), WaitState::Uninterruptible);
    }

    #[test]
    fn an_idle_event_worker_is_not_a_hung_task_candidate() {
        let observation = crate::hung_task::Observation {
            state: crate::TaskState::Sleeping,
            wait: event_worker(),
            switch_count: 7,
            last_switch_count: 7,
            last_switch_ns: 0,
            now_ns: 121_000_000_000,
        };
        assert_eq!(crate::hung_task::classify(observation, 120), crate::hung_task::Verdict::Skip);
    }
}
