// Interruptible-sleep signal triage — Linux `signal_pending_state(
// TASK_INTERRUPTIBLE, task)` plus `get_signal`'s job-control-stop arm,
// resolved into the ONE decision every sleeping syscall makes.
//
// nanosleep(2) (035), pause(2) (034) and clock_nanosleep(2) (230) each carried
// a private copy of this triage. The clock_nanosleep copy tested the RAW
// `sigpending & !sigmask`, so a signal Linux drops at send time
// (`kernel/signal.c` `sig_ignored`/`prepare_signal`: SIG_IGN, or SIG_DFL whose
// signal(7) default action is Ignore) truncated the sleep — a SIGWINCH
// terminal resize or a SIGURG cut every `clock_nanosleep` short. Lives on
// `Task` next to `deliverable_signals` so there is one owner, not four.

use super::Task;
use crate::signum::{self, DefaultAction, Signum};

/// SIG_DFL — the disposition whose behaviour comes from signal(7).
const SIG_DFL: u64 = 0;

/// What an interruptible sleeper must do about its pending set.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SleepWake {
    /// Nothing the return path would act on — keep sleeping.
    None,
    /// A deliverable signal: abort the wait so the syscall-return tail runs
    /// Linux `get_signal` (handler frame, SIG_DFL terminate, or an ERESTART*
    /// restart decision).
    Deliver,
    /// A SIG_DFL job-control stop (`DefaultAction::Stop`): stop here, then
    /// resume the SAME wait once SIGCONT arrives.
    Stop(u32),
}

impl Task {
    /// Linux's interruptible-sleep wake test. The decision set is
    /// [`Task::deliverable_signals`] — the `sig_ignored`-filtered pending set
    /// — so an ignored signal never wakes the sleeper. The LOWEST deliverable
    /// signal decides, matching `dequeue_signal`/`next_signal` order.
    ///
    /// Linux drops an ignored signal at send time, so it is never pending at
    /// all; this kernel posts every signal and filters at the consumer, so the
    /// ignored-but-pending bits are cleared here to reach the same end state
    /// (a sleeper that parks forever must not leave them in `SigPnd`).
    /// # C: O(N_sig)
    pub fn sleep_wake(&self) -> SleepWake {
        use core::sync::atomic::Ordering;
        let deliverable = self.deliverable_signals();
        let unmasked = self.sigpending.load(Ordering::Acquire)
            & !self.sigmask.load(Ordering::Acquire);
        let mut ignored = unmasked & !deliverable;
        while ignored != 0 {
            let sig = ignored.trailing_zeros() + 1;
            ignored &= !(1u64 << (sig - 1));
            self.flush_pending_signal(sig as usize);
        }
        if deliverable == 0 { return SleepWake::None; }
        let sig = deliverable.trailing_zeros() + 1;
        if self.sigactions_ref().get(sig).handler == SIG_DFL
            && signum::default_action(sig) == DefaultAction::Stop
        {
            // Linux `do_signal_stop` consumes the stop signal before parking.
            self.flush_pending_signal(sig as usize);
            return SleepWake::Stop(sig);
        }
        SleepWake::Deliver
    }
}

/// Linux `TASK_INTERRUPTIBLE` vs `TASK_KILLABLE`, as
/// `signal_pending_state(state, current)` distinguishes them
/// (`include/linux/sched/signal.h:409-417`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WaitState {
    /// `TASK_INTERRUPTIBLE` — any deliverable signal ends the wait.
    Interruptible,
    /// `TASK_KILLABLE` (`TASK_WAKEKILL | TASK_UNINTERRUPTIBLE`) — only a
    /// fatal signal does.
    Killable,
}

/// The three exits of `___wait_event`. A typed outcome rather than a bare
/// `i64` so a caller physically cannot drop the interrupted case the way 46
/// hand-rolled loops did.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WaitOutcome {
    /// The condition became true.
    Ready,
    /// `signal_pending_state()` held — Linux returns `-ERESTARTSYS` here,
    /// NEVER `-EINTR`. The syscall-return tail decides what userspace sees.
    Interrupted,
    /// The absolute deadline passed before the condition became true.
    TimedOut,
}

impl WaitOutcome {
    /// True for the one outcome that must not be treated as a normal result.
    /// # C: O(1)
    pub const fn interrupted(self) -> bool { matches!(self, WaitOutcome::Interrupted) }
}

/// Linux `signal_pending_state(state, p)` (`sched/signal.h:409-417`):
///
/// ```text
/// if (!(state & (TASK_INTERRUPTIBLE | TASK_WAKEKILL))) return 0;
/// if (!signal_pending(p)) return 0;
/// return (state & TASK_INTERRUPTIBLE) || __fatal_signal_pending(p);
/// ```
///
/// `signal_pending(p)` is [`Task::deliverable_signals`], the `sig_ignored`-
/// filtered set. `__fatal_signal_pending` is SIGKILL ONLY
/// (`sched/signal.h:399-402`) — not SIGSTOP, which stops rather than kills, so
/// a killable sleeper must stay asleep across a job-control stop.
/// # C: O(N_sig)
pub fn signal_pending_state(task: &Task, state: WaitState) -> bool {
    let deliverable = task.deliverable_signals();
    if deliverable == 0 { return false; }
    match state {
        WaitState::Interruptible => true,
        WaitState::Killable => deliverable & Signum::Sigkill.bit() != 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::{SaHandler, SchedClass, Task};
    use crate::signum::Signum;
    use core::sync::atomic::Ordering;

    const SIG_IGN: u64 = 1;
    const HANDLER: u64 = 0x5555_7430;

    fn task() -> Task { Task::new(0x7430, "sigwake", SchedClass::Normal { weight: 1024 }) }

    fn act(t: &Task, sig: Signum, handler: u64) {
        t.rt_sigaction(sig as usize, Some(SaHandler { handler, flags: 0, restorer: 0, mask: 0 })).unwrap();
    }

    fn raise(t: &Task, sig: Signum) { t.sigpending.fetch_or(sig.bit(), Ordering::Release); }

    #[test]
    fn empty_pending_set_keeps_sleeping() {
        assert_eq!(task().sleep_wake(), SleepWake::None);
    }

    #[test]
    fn default_ignored_signals_never_truncate_a_sleep() {
        // Linux SIG_KERNEL_IGNORE_MASK (`include/linux/signal.h:434-436`):
        // SIGCHLD, SIGCONT, SIGWINCH, SIGURG are dropped at send time, so a
        // terminal resize can never cut a sleep short.
        for sig in [Signum::Sigwinch, Signum::Sigurg, Signum::Sigchld, Signum::Sigcont] {
            let t = task();
            raise(&t, sig);
            assert_eq!(t.sleep_wake(), SleepWake::None, "sig={sig:?}");
            assert_eq!(t.sigpending.load(Ordering::Acquire) & sig.bit(), 0,
                "an ignored signal must not stay pending");
        }
    }

    #[test]
    fn explicitly_ignored_signal_never_truncates_a_sleep() {
        let t = task();
        act(&t, Signum::Sigusr1, SIG_IGN);
        raise(&t, Signum::Sigusr1);
        assert_eq!(t.sleep_wake(), SleepWake::None);
    }

    #[test]
    fn caught_signal_wakes_the_sleeper() {
        let t = task();
        act(&t, Signum::Sigusr1, HANDLER);
        raise(&t, Signum::Sigusr1);
        assert_eq!(t.sleep_wake(), SleepWake::Deliver);
        assert_ne!(t.sigpending.load(Ordering::Acquire) & Signum::Sigusr1.bit(), 0,
            "the return tail dequeues it, not the sleeper");
    }

    #[test]
    fn masked_signal_does_not_wake_but_unblockable_ones_do() {
        let t = task();
        act(&t, Signum::Sigusr1, HANDLER);
        t.set_current_blocked(Signum::Sigusr1.bit());
        raise(&t, Signum::Sigusr1);
        assert_eq!(t.sleep_wake(), SleepWake::None);
        raise(&t, Signum::Sigkill);
        assert_eq!(t.sleep_wake(), SleepWake::Deliver);
    }

    #[test]
    fn a_fully_masked_task_is_still_killable() {
        // Linux strips SIGKILL/SIGSTOP from every mask install, so
        // `pending & ~blocked` always shows them. A raw `sigmask` write must
        // not be able to make a sleeper unkillable.
        let t = task();
        t.sigmask.store(u64::MAX, Ordering::Release);
        raise(&t, Signum::Sigkill);
        assert_eq!(t.sleep_wake(), SleepWake::Deliver);
        // SIGSTOP is unblockable too, and its SIG_DFL action is the stop.
        let t = task();
        t.sigmask.store(u64::MAX, Ordering::Release);
        raise(&t, Signum::Sigstop);
        assert_eq!(t.sleep_wake(), SleepWake::Stop(Signum::Sigstop as u32));
    }

    #[test]
    fn default_stop_signal_reports_stop_and_consumes_it() {
        let t = task();
        raise(&t, Signum::Sigtstp);
        assert_eq!(t.sleep_wake(), SleepWake::Stop(Signum::Sigtstp as u32));
        assert_eq!(t.sigpending.load(Ordering::Acquire) & Signum::Sigtstp.bit(), 0);
        // A caught SIGTSTP is an ordinary delivery, not a stop.
        let t = task();
        act(&t, Signum::Sigtstp, HANDLER);
        raise(&t, Signum::Sigtstp);
        assert_eq!(t.sleep_wake(), SleepWake::Deliver);
    }

    #[test]
    fn lowest_deliverable_signal_decides() {
        // SIGWINCH (ignored) must not mask SIGUSR1's delivery, and the lower
        // of two deliverable signals picks the verdict.
        let t = task();
        act(&t, Signum::Sigusr1, HANDLER);
        raise(&t, Signum::Sigwinch);
        raise(&t, Signum::Sigusr1);
        assert_eq!(t.sleep_wake(), SleepWake::Deliver);
        let t = task();
        act(&t, Signum::Sigusr1, HANDLER);
        raise(&t, Signum::Sigtstp);   // 20, default stop
        raise(&t, Signum::Sigusr1);   // 10, caught
        assert_eq!(t.sleep_wake(), SleepWake::Deliver);
    }

    #[test]
    fn an_empty_pending_set_ends_neither_kind_of_wait() {
        let t = task();
        assert!(!signal_pending_state(&t, WaitState::Interruptible));
        assert!(!signal_pending_state(&t, WaitState::Killable));
    }

    #[test]
    fn a_caught_signal_ends_an_interruptible_wait_but_not_a_killable_one() {
        let t = task();
        act(&t, Signum::Sigusr1, HANDLER);
        raise(&t, Signum::Sigusr1);
        assert!(signal_pending_state(&t, WaitState::Interruptible));
        // `(state & TASK_INTERRUPTIBLE) || __fatal_signal_pending(p)` — a killable
        // sleeper ignores everything that is not SIGKILL.
        assert!(!signal_pending_state(&t, WaitState::Killable));
    }

    #[test]
    fn sigkill_ends_both_kinds() {
        let t = task();
        raise(&t, Signum::Sigkill);
        assert!(signal_pending_state(&t, WaitState::Interruptible));
        assert!(signal_pending_state(&t, WaitState::Killable));
    }

    #[test]
    fn sigstop_is_not_fatal_so_a_killable_wait_survives_a_job_control_stop() {
        // `__fatal_signal_pending` tests SIGKILL ONLY (`sched/signal.h:399-402`).
        // SIGSTOP stops the task rather than killing it, so a killable sleeper
        // must stay asleep across it — treating UNBLOCKABLE (KILL|STOP) as fatal
        // would end uninterruptible waits on a plain job-control stop.
        let t = task();
        raise(&t, Signum::Sigstop);
        assert!(signal_pending_state(&t, WaitState::Interruptible));
        assert!(!signal_pending_state(&t, WaitState::Killable));
    }

    #[test]
    fn an_ignored_signal_ends_neither_kind() {
        // `signal_pending(p)` is the `sig_ignored`-filtered set, so SIG_IGN and
        // the default-ignore dispositions never wake a sleeper at all.
        let t = task();
        act(&t, Signum::Sigusr1, SIG_IGN);
        raise(&t, Signum::Sigusr1);
        for sig in [Signum::Sigwinch, Signum::Sigurg, Signum::Sigchld] { raise(&t, sig); }
        assert!(!signal_pending_state(&t, WaitState::Interruptible));
        assert!(!signal_pending_state(&t, WaitState::Killable));
    }

    #[test]
    fn a_masked_signal_ends_neither_kind_but_a_masked_sigkill_still_kills() {
        use core::sync::atomic::Ordering;
        let t = task();
        act(&t, Signum::Sigusr1, HANDLER);
        t.set_current_blocked(Signum::Sigusr1.bit());
        raise(&t, Signum::Sigusr1);
        assert!(!signal_pending_state(&t, WaitState::Interruptible));
        // SIGKILL can never be blocked, so a fully-masked task stays killable.
        t.sigmask.store(u64::MAX, Ordering::Release);
        raise(&t, Signum::Sigkill);
        assert!(signal_pending_state(&t, WaitState::Killable));
    }

    #[test]
    fn the_interrupted_outcome_is_the_only_one_flagged_for_restart() {
        assert!(WaitOutcome::Interrupted.interrupted());
        assert!(!WaitOutcome::Ready.interrupted());
        assert!(!WaitOutcome::TimedOut.interrupted());
    }
}
