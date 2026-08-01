// The ONE signal-generation contract: how a signal becomes pending.
//
// Linux has exactly one enqueue function (`__send_signal_locked`) and one
// forced-delivery wrapper (`force_sig_info_to_task`). Every producer — kill(2),
// tgkill, the fault classifiers, POSIX timers, tty job control, SIGCHLD, SIGPIPE,
// the OOM killer — funnels through them. This kernel used to have ~40 producers
// open-coding `t.sigpending.fetch_or(bit)`, which meant each one independently
// forgot some subset of: the queued `siginfo_t`, the private-vs-shared set
// choice, `prepare_signal`'s SIGCONT/stop flush, and the wake.
//
// The DECISIONS live here, ungated, so they are `cargo test -p sched` provable.
// The mechanism (registry walk, wake, queue push) is `live::send`, which is
// kernel-only and cannot be hosted-tested.
//
// Module manifest — this file owns:
//   * `SigTarget`  — Linux `enum pid_type`'s private/shared discriminant.
//   * `SigSource`  — Linux `SEND_SIG_NOINFO` / `SEND_SIG_PRIV` / explicit info.
//   * `build_info` — `__send_signal_locked`'s siginfo synthesis.
//   * `sig_ignored`/`prepare_flush` — `prepare_signal`'s two halves.
//   * `force_decision` — `force_sig_info_to_task`'s unblock/reset ladder.

use crate::signum::{self, DefaultAction, Signum, SI_KERNEL, SI_USER};
use crate::task::SigInfo;

/// SIG_DFL sentinel (Linux uapi `sa_handler`). Never inline as a bare 0.
pub const SIG_DFL: u64 = 0;
/// SIG_IGN sentinel.
pub const SIG_IGN: u64 = 1;

/// Which pending set the signal joins — Linux `__send_signal_locked`'s
/// `pending = (type != PIDTYPE_PID) ? &t->signal->shared_pending : &t->pending`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SigTarget {
    /// `PIDTYPE_PID` — this THREAD's private set. What `tgkill(2)`, `tkill(2)`
    /// and every synchronous fault signal use.
    Thread,
    /// `PIDTYPE_TGID` and wider — the PROCESS' shared set. What `kill(2)`,
    /// `sigqueue(3)`, a process-directed POSIX timer and tty job control use.
    Process,
}

/// Linux's three `struct kernel_siginfo *` conventions at a send site.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SigSource {
    /// `SEND_SIG_NOINFO` — a user-originated send with no explicit record.
    /// The receiver still gets `si_code = SI_USER` plus the sender's pid/uid.
    User { pid: u32, uid: u32 },
    /// `SEND_SIG_PRIV` — kernel-generated, `si_code = SI_KERNEL`, pid/uid 0.
    /// `force = true`: a SIG_IGN disposition does NOT suppress it.
    Kernel,
    /// An explicit, fully-populated record (`sigqueue(3)`, a POSIX timer, a
    /// fault classifier, SIGCHLD's child-exit event).
    Info(SigInfo),
}

impl SigSource {
    /// Linux `si_fromuser(info)` — whether `check_kill_permission` applies.
    /// # C: O(1)
    pub fn from_user(&self) -> bool {
        match self {
            SigSource::User { .. } => true,
            SigSource::Kernel => false,
            SigSource::Info(i) => i.code == SI_USER || i.code < 0,
        }
    }

    /// Linux `send_signal_locked`'s `force`: a kernel-generated signal is not
    /// suppressed by a SIG_IGN disposition.
    /// # C: O(1)
    pub fn force(&self) -> bool {
        match self {
            SigSource::Kernel => true,
            SigSource::Info(i) => i.code == SI_KERNEL,
            SigSource::User { .. } => false,
        }
    }
}

/// Linux `__send_signal_locked`'s siginfo synthesis: `SEND_SIG_NOINFO` fills
/// `SI_USER` + the sender's identity, `SEND_SIG_PRIV` fills `SI_KERNEL` with
/// zero identity, and an explicit record is copied verbatim with `si_signo`
/// forced to the signal actually being sent.
/// # C: O(1)
pub fn build_info(sig: u32, src: SigSource) -> SigInfo {
    match src {
        SigSource::User { pid, uid } =>
            SigInfo { signo: sig, code: SI_USER, pid, uid, value: 0, sys: None, fault: None, poll: None },
        SigSource::Kernel =>
            SigInfo { signo: sig, code: SI_KERNEL, pid: 0, uid: 0, value: 0, sys: None, fault: None, poll: None },
        SigSource::Info(mut i) => { i.signo = sig; i }
    }
}

/// Linux `sig_handler_ignored`: SIG_IGN, or SIG_DFL for a default-ignore
/// signal. SIGCONT is NOT in this set — its default action is Continue, which
/// has an observable effect (resuming a stopped group) and must still be sent.
/// # C: O(1)
pub fn handler_ignored(handler: u64, sig: u32) -> bool {
    handler == SIG_IGN
        || (handler == SIG_DFL && signum::default_action(sig) == DefaultAction::Ign)
}

/// Linux `sig_ignored`: whether the send is dropped outright.
///
/// A BLOCKED signal is never ignored — it must stay pending so an
/// `rt_sigtimedwait`/`sigwait`/signalfd consumer can still collect it, and so
/// `rt_sigprocmask` unblocking it later delivers it. A traced task never drops
/// anything but SIGKILL, since the tracer must see every signal. `force`
/// (`SEND_SIG_PRIV`) overrides the disposition entirely.
/// # C: O(1)
pub fn sig_ignored(handler: u64, sig: u32, blocked: u64, force: bool, ptraced: bool) -> bool {
    if signum::is_unblockable(sig) { return false; }
    if let Some(bit) = signum::bit_for(sig) { if blocked & bit != 0 { return false; } }
    if ptraced && sig != Signum::Sigkill as u32 { return false; }
    if force { return false; }
    handler_ignored(handler, sig)
}

/// Linux `prepare_signal`'s flush arm: sending a job-control STOP discards a
/// pending SIGCONT and vice versa, because the two are mutually contradictory
/// states. Returns the pending mask the receiver must drop before the new
/// signal is queued.
/// # C: O(1)
pub fn prepare_flush(sig: u32) -> u64 {
    if sig == Signum::Sigcont as u32 { return STOP_MASK; }
    if matches!(signum::default_action(sig), DefaultAction::Stop) { return Signum::Sigcont.bit(); }
    0
}

/// The four job-control stop signals — Linux `SIG_KERNEL_STOP_MASK`.
pub const STOP_MASK: u64 = Signum::Sigstop.bit() | Signum::Sigtstp.bit()
    | Signum::Sigttin.bit() | Signum::Sigttou.bit();

/// Linux `enum sig_handler` — how forcefully a `force_sig_info` delivery
/// insists on the default action.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ForceMode {
    /// `HANDLER_CURRENT` — keep an installed handler if the signal is neither
    /// blocked nor ignored. Every fault classifier uses this.
    Current,
    /// `HANDLER_SIG_DFL` — always reset to SIG_DFL, keep the task killable.
    SigDfl,
    /// `HANDLER_EXIT` — reset to SIG_DFL and mark the action `SA_IMMUTABLE`;
    /// the process dies no matter what (`force_fatal_sig`, seccomp KILL).
    Exit,
}

/// What `force_sig_info_to_task` must mutate before it queues the signal.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct ForceOutcome {
    /// Overwrite the action slot with SIG_DFL.
    pub reset_to_dfl: bool,
    /// Remove the signal from the receiver's blocked mask.
    pub unblock: bool,
    /// `action->sa.sa_flags |= SA_IMMUTABLE` — the disposition is now frozen.
    /// A later `rt_sigaction` on this signal is EINVAL, and the tracer's
    /// signal-delivery stop is skipped for it, so neither the process nor a
    /// debugger can turn a forced-fatal signal back into a survivable one.
    pub immutable: bool,
}

/// Linux `force_sig_info_to_task`'s ladder: "if necessary we unblock the
/// signal and change any SIG_IGN to SIG_DFL".
///
/// The reset is deliberately unconditional once ANY of the three triggers
/// fires — Linux's comment is explicit that an unblocked-by-force signal must
/// never reach a handler userspace had explicitly blocked.
/// # C: O(1)
pub fn force_decision(handler: u64, sig: u32, blocked: u64, mode: ForceMode) -> ForceOutcome {
    let ignored = handler == SIG_IGN;
    let blocked_here = signum::bit_for(sig).is_some_and(|b| blocked & b != 0);
    let forced = mode != ForceMode::Current;
    let immutable = mode == ForceMode::Exit;
    if blocked_here || ignored || forced {
        ForceOutcome { reset_to_dfl: true, unblock: blocked_here, immutable }
    } else {
        ForceOutcome::default()
    }
}

/// Linux `legacy_queue`: a standard (non-real-time) signal already pending
/// keeps its FIRST record; a second send is collapsed onto the same bit and its
/// record dropped. Real-time signals queue instead.
/// # C: O(1)
pub fn legacy_queue(sig: u32, pending: u64) -> bool {
    !signum::is_realtime(sig) && signum::bit_for(sig).is_some_and(|b| pending & b != 0)
}

/// Linux `__send_signal_locked`'s `override_rlimit`: a standard signal, or one
/// carrying a kernel-origin `si_code`, is queued even at the `RLIMIT_SIGPENDING`
/// ceiling — `kill(2)` is not allowed to fail with EAGAIN. Only a real-time
/// signal from a user queueing mechanism can overflow.
/// # C: O(1)
pub fn override_rlimit(sig: u32, src: &SigSource) -> bool {
    if signum::is_realtime(sig) { return false; }
    match src {
        SigSource::User { .. } | SigSource::Kernel => true,
        SigSource::Info(i) => i.code >= 0,
    }
}

/// Linux `__send_signal_locked`'s queue-overflow arm: when the record could not
/// be allocated, the send fails with EAGAIN only for a real-time signal that a
/// user queueing mechanism (not `kill(2)`) originated. Everything else is a
/// "silent loss of information" — the bit is still set, the record is lost.
/// # C: O(1)
pub fn overflow_is_eagain(sig: u32, src: &SigSource) -> bool {
    if !signum::is_realtime(sig) { return false; }
    match src {
        SigSource::Kernel => false,
        SigSource::User { .. } => false,
        SigSource::Info(i) => i.code != SI_USER,
    }
}

/// Build the `_sigfault` record `force_sig_fault(sig, code, addr)` queues.
/// # C: O(1)
pub fn fault_info(sig: u32, code: i32, addr: u64, addr_lsb: i16) -> SigInfo {
    SigInfo {
        signo: sig, code, pid: 0, uid: 0, value: 0, sys: None,
        fault: Some(hal::SigFault { addr, addr_lsb }), poll: None,
    }
}

#[cfg(test)]
mod tests;
