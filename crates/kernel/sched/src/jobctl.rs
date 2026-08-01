// `task->jobctl` — the job-control / ptrace-trap latch, and the decisions
// `do_signal_stop`, `ptrace_stop`, `do_jobctl_trap` and
// `task_participate_group_stop` make from it.
//
// UNGATED on purpose: every rule below decides which parent is told about a
// stop, with which `si_code`, and whether a resume is an observable
// `wait4(WCONTINUED)` event. Those are exactly the answers a hosted test must
// be able to check, so no part of this file may be behind a target gate.
// The latch itself is `Task::jobctl`; the parking is `live::stop`.
//
// Module manifest — this file owns:
//   * the `JOBCTL_*` bit layout and `TRAP_MASK` / `PENDING_MASK`.
//   * `set_pending` / `clear_pending` — Linux's two latch mutators.
//   * `participate_group_stop` — the group-stop completion counter rule.
//   * `StopKind` / `WakeKind` and the notify-target / notify-`si_code` /
//     `CLD_CONTINUED` rules that separate a job-control stop from a ptrace stop.
//   * `listen` / `retrap_pending` — PTRACE_LISTEN's latch.

use crate::exit::notify::Cldstop;

/// Low 16 bits: the signal number of the group stop in progress.
pub const STOP_SIGMASK: u64 = 0xffff;
/// A stop signal was dequeued and this task owes the group a stop.
pub const STOP_DEQUEUED: u64 = 1 << 16;
/// This task must stop for the group stop.
pub const STOP_PENDING: u64 = 1 << 17;
/// This task still owes the group-stop counter a decrement.
pub const STOP_CONSUME: u64 = 1 << 18;
/// Trap for STOP — a seized tracee owes its tracer a `PTRACE_EVENT_STOP`.
pub const TRAP_STOP: u64 = 1 << 19;
/// Trap for NOTIFY — an asynchronous event (a SIGCONT, a group stop starting)
/// arrived while the tracee was trapped, so the trap must be reported again.
pub const TRAP_NOTIFY: u64 = 1 << 20;
/// The tracer issued `PTRACE_LISTEN`: the tracee stays stopped but an
/// asynchronous event re-traps it instead of being silently swallowed.
pub const LISTENING: u64 = 1 << 22;
/// Parked in a job-control stop.
pub const STOPPED: u64 = 1 << 26;
/// Parked in a ptrace stop.
pub const TRACED: u64 = 1 << 27;

/// Both trap latches — what `do_jobctl_trap` acts on.
pub const TRAP_MASK: u64 = TRAP_STOP | TRAP_NOTIFY;
/// Everything a dying or resumed task must have cleared.
pub const PENDING_MASK: u64 = STOP_PENDING | TRAP_MASK;

/// `CLD_TRAPPED` si_code — a ptrace stop, reported to the TRACER.
pub const CLD_TRAPPED: i32 = 4;

/// Which kind of stop a task is parking in. The two differ in who is told and
/// with which `si_code`, and in whether the resume is a `wait4(WCONTINUED)`
/// event — conflating them made every `PTRACE_CONT` post a spurious
/// `SIGCHLD`/`CLD_CONTINUED` to the tracee's real parent.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StopKind {
    /// `do_signal_stop` — SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU took its default
    /// action. Reported to the REAL parent as `CLD_STOPPED`, and its resume by
    /// SIGCONT is reported as `CLD_CONTINUED`.
    JobControl,
    /// `ptrace_stop` — a syscall stop, an event stop or a signal-delivery
    /// stop. Reported to the TRACER as `CLD_TRAPPED`; the resume is not an
    /// event at all.
    Ptrace,
}

/// Why a stopped task was made runnable again. `repr(u8)` because the wake
/// site publishes it into `Task::stop_wake` for the waking task to read back.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WakeKind {
    /// A real SIGCONT reached the group — the only `CLD_CONTINUED` producer.
    Cont = 0,
    /// `ptrace_resume` / `ptrace_detach` / a tracer's death. Linux publishes
    /// `child->exit_code` and wakes; it generates no `SIGCHLD` of any kind.
    PtraceResume = 1,
    /// A fatal signal or `zap_other_threads` — the task is being resumed only
    /// so it can die, which is not a continue event either.
    Kill = 2,
}

impl WakeKind {
    /// Decode a `Task::stop_wake` byte. An unrecognised value is the
    /// conservative `Kill`, which notifies nothing. # C: O(1)
    pub const fn from_u8(v: u8) -> Self {
        match v { 0 => WakeKind::Cont, 1 => WakeKind::PtraceResume, _ => WakeKind::Kill }
    }
}

/// Who the stop notification goes to.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NotifyTarget {
    /// `do_notify_parent_cldstop(..., for_ptracer = false)` — `real_parent`.
    RealParent,
    /// `do_notify_parent_cldstop(..., for_ptracer = true)` — `parent`, which
    /// for a traced task is the tracer.
    Tracer,
}

/// Who is told when a task parks in `kind`. # C: O(1)
pub const fn notify_target(kind: StopKind) -> NotifyTarget {
    match kind { StopKind::Ptrace => NotifyTarget::Tracer, StopKind::JobControl => NotifyTarget::RealParent }
}

/// The `si_code` the stop notification carries. # C: O(1)
pub const fn stop_si_code(kind: StopKind) -> Cldstop {
    match kind { StopKind::Ptrace => Cldstop::Trapped, StopKind::JobControl => Cldstop::Stopped }
}

/// What a resume owes the parent.
///
/// Only a job-control stop ended by a real SIGCONT is a `CLD_CONTINUED` event.
/// A ptrace resume generates nothing: Linux's `ptrace_resume` writes
/// `child->exit_code` and wakes the tracee, and never reaches
/// `do_notify_parent_cldstop`. A kill-wake generates nothing either — the task
/// is only being resumed to run its own death.
/// # C: O(1)
pub const fn resume_notify(kind: StopKind, wake: WakeKind) -> Option<Cldstop> {
    match (kind, wake) {
        (StopKind::JobControl, WakeKind::Cont) => Some(Cldstop::Continued),
        _ => None,
    }
}

/// Whether this wake is the `wait4(WCONTINUED)` event `cont_pending` records.
/// Same rule as `resume_notify`, stated for the wake site, which knows the
/// reason but not the stop kind.
/// # C: O(1)
pub const fn records_continued(wake: WakeKind) -> bool { matches!(wake, WakeKind::Cont) }

/// Linux `task_set_jobctl_pending`: refuse to arm a new trap on a task that is
/// already dying (a pending fatal signal or `PF_EXITING`), and drop
/// `STOP_PENDING`'s companions when the task is not actually going to stop.
/// Returns the new latch, or `None` when the arm is refused.
/// # C: O(1)
pub const fn set_pending(jobctl: u64, mask: u64, dying: bool) -> Option<u64> {
    if dying && mask & (STOP_SIGMASK | STOP_PENDING | TRAP_MASK) != 0 { return None; }
    let mut new = jobctl | mask;
    // "Only the group-stop signal in progress is remembered": a second arm
    // with a different signal replaces the recorded one rather than OR-ing
    // two signal numbers into one field.
    if mask & STOP_SIGMASK != 0 { new = (new & !STOP_SIGMASK) | (mask & STOP_SIGMASK); }
    Some(new)
}

/// Linux `task_clear_jobctl_pending`. Clearing `STOP_PENDING` also clears the
/// recorded signal and the unconsumed counter debt, since neither means
/// anything without a stop to belong to.
/// # C: O(1)
pub const fn clear_pending(jobctl: u64, mask: u64) -> u64 {
    let mut m = mask;
    if m & STOP_PENDING != 0 { m |= STOP_SIGMASK | STOP_CONSUME; }
    jobctl & !m
}

/// What `task_participate_group_stop` decides for one thread joining the stop.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GroupStopStep {
    /// The thread's latch after it joined.
    pub jobctl: u64,
    /// The group's remaining outstanding-thread count.
    pub count: u32,
    /// This thread was the LAST to stop, so the group stop is now complete and
    /// the real parent is owed exactly ONE `CLD_STOPPED`.
    pub completed: bool,
}

/// Linux `task_participate_group_stop`.
///
/// A thread only decrements the group counter when it still carries
/// `STOP_CONSUME` — the debt is one per thread, so a thread that stops twice
/// (a tracee re-stopped by its tracer) cannot drive the counter below zero and
/// report a second, spurious group-stop completion to the real parent.
///
/// `already_stopped` is the group's `SIGNAL_STOP_STOPPED` latch: completion is
/// reported only when entering a FRESH group stop. A thread joining a stop the
/// group has already completed owes nobody a second `CLD_STOPPED`.
/// # C: O(1)
pub const fn participate_group_stop(jobctl: u64, count: u32, already_stopped: bool)
    -> GroupStopStep
{
    let consume = jobctl & STOP_CONSUME != 0;
    let jobctl = clear_pending(jobctl, STOP_PENDING);
    if !consume { return GroupStopStep { jobctl, count, completed: false }; }
    let count = count.saturating_sub(1);
    GroupStopStep { jobctl, count, completed: count == 0 && !already_stopped }
}

/// `PTRACE_LISTEN`'s latch: `LISTENING` alone. It arms no trap — the tracee is
/// already parked in one. The bit's only job is to make `trap_notify` WAKE the
/// tracee when an asynchronous event arms `TRAP_NOTIFY`, so it can leave the
/// trap and immediately re-enter it with the event reported.
/// # C: O(1)
pub const fn listen(jobctl: u64) -> u64 { jobctl | LISTENING }

/// Whether an already-latched `TRAP_NOTIFY` must re-trap the tracee NOW.
///
/// `PTRACE_LISTEN` races the event it is listening for: an event that landed
/// between the tracee entering the trap and the tracer issuing LISTEN has
/// already set `TRAP_NOTIFY`, and there is no second event coming to wake it.
/// Linux re-triggers the trap from inside `PTRACE_LISTEN` for exactly that
/// window; without it the tracee sleeps forever holding a report nobody sees.
/// # C: O(1)
pub const fn retrap_pending(jobctl: u64) -> bool { jobctl & TRAP_NOTIFY != 0 }

/// Linux `ptrace_trap_notify`: an asynchronous event reaching a SEIZED tracee
/// arms `TRAP_NOTIFY`, and only actually WAKES the tracee when it is
/// `LISTENING`. A tracee sitting in an ordinary ptrace stop keeps sleeping —
/// its tracer is going to resume it and will see the latch then.
/// # C: O(1)
pub const fn trap_notify(jobctl: u64) -> (u64, bool) {
    (jobctl | TRAP_NOTIFY, jobctl & LISTENING != 0)
}

/// Whether a task leaving a trap owes another one immediately.
///
/// The condition is the TRAP LATCH, not `LISTENING`: a tracee woken with
/// `TRAP_NOTIFY` still set has an event nobody has been told about, so it
/// re-enters the trap and reports it. `LISTENING` only decides whether the
/// tracee gets WOKEN in the first place (`trap_notify`), and it is dropped on
/// the way out of every trap — which is why `PTRACE_LISTEN` is per-stop and
/// the tracer must re-issue it after each report.
///
/// A kill-wake never re-traps: a `PTRACE_LISTEN` that could swallow a SIGKILL
/// would make a process immortal. A tracer's own resume never re-traps either
/// — it cleared the latch when it published the resume.
/// # C: O(1)
pub const fn wake_retraps(jobctl: u64, wake: WakeKind) -> bool {
    !matches!(wake, WakeKind::Kill | WakeKind::PtraceResume) && jobctl & TRAP_MASK != 0
}

/// What entering a trap clears: any trap clears a pending `TRAP_STOP`, and a
/// trap that REPORTS `PTRACE_EVENT_STOP` also settles the `TRAP_NOTIFY` that
/// asked for it — the event it names has now been announced.
/// # C: O(1)
pub const fn trap_entry_clears(jobctl: u64, reports_event_stop: bool) -> u64 {
    let mask = if reports_event_stop { TRAP_MASK } else { TRAP_STOP };
    clear_pending(jobctl, mask)
}

/// What LEAVING a trap clears. `LISTENING` can only be set during a stop trap,
/// so it is dropped here, on the tracee — not by the tracer's resume.
/// # C: O(1)
pub const fn stop_exit_clears(jobctl: u64) -> u64 { jobctl & !(LISTENING | TRACED) }

/// `ptrace_resume` clears `JOBCTL_TRACED` and nothing else. The trap latch is
/// the TRACEE's to settle as it leaves the stop; a tracer that cleared it here
/// would discard an event the tracee had not yet reported.
/// # C: O(1)
pub const fn resume_clears(jobctl: u64) -> u64 { jobctl & !TRACED }

#[cfg(test)]
#[path = "jobctl/tests.rs"] mod tests;
