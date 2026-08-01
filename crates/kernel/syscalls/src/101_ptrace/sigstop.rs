// Signal-delivery-stop policy — Linux `get_signal`'s ptrace arm plus
// `ptrace_signal`'s tail. UNGATED: this is the ordering that decides whether a
// signal is delivered, replaced or dropped, so it must be reachable from
// `cargo test`. The park itself is `101_ptrace/stop.rs`.
//
// The stop sits between `dequeue_signal` and the disposition switch: the
// signal has already been consumed from the pending set when the tracee stops,
// and whatever the tracer names on resume is what the disposition switch then
// acts on.

use sched::signum::Signum;

/// What the delivery path does with a signal after the tracer resumed us.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Outcome {
    /// Deliver this signal. `substituted` is true when the tracer named a
    /// DIFFERENT signal than the one reported, which means the siginfo must be
    /// rebuilt as an `SI_USER` record attributed to the tracer — the original
    /// record described a different signal entirely.
    Deliver { sig: u32, substituted: bool },
    /// The tracer cancelled the signal (`data == 0`). It is simply gone: it
    /// was already dequeued, so nothing re-posts it.
    Suppress,
    /// The signal survives but cannot be delivered on this pass — it is
    /// blocked now, or the task is dying. Re-post it and deliver nothing.
    Requeue { sig: u32 },
}

/// `SI_USER` — the `si_code` a substituted signal's rebuilt record carries.
pub const SI_USER: i32 = 0;

/// Linux `get_signal`'s gate:
/// `if (unlikely(current->ptrace) && (signr != SIGKILL) && !SA_IMMUTABLE)`.
///
/// SIGKILL is excluded outright: a tracer must never be able to stop, inspect
/// or cancel the one signal that guarantees a process can be killed. Every
/// other signal — SIGSTOP included — goes through the tracer first, which is
/// how a debugger sees and suppresses the `SIGSTOP` its own `PTRACE_ATTACH`
/// posted.
///
/// `immutable` is the third term, and it is the one that was missing: a signal
/// forced with `HANDLER_EXIT` (`force_fatal_sig`, a seccomp `RET_KILL_*`) has
/// its action marked `SA_IMMUTABLE`, and Linux then skips the stop entirely.
/// Without it a tracer could catch a forced-fatal SIGSEGV/SIGSYS at its
/// delivery stop and resume with signal 0, cancelling a death the kernel had
/// already decided was not negotiable — a sandbox escape from any process able
/// to trace itself.
/// # C: O(1)
pub fn stops_for_tracer(traced: bool, sig: u32, immutable: bool) -> bool {
    traced && sig != Signum::Sigkill as u32 && !immutable
}

/// `ptrace_signal`'s tail, run once the tracee is back from the stop.
///
/// `resume_sig` is what the tracer wrote with `PTRACE_CONT`/`SYSCALL`/
/// `SINGLESTEP`/`DETACH`'s `data`; a tracee woken by something other than the
/// tracer (a fatal signal, the tracer dying) still reads back the signal it
/// reported, so the original is delivered rather than lost.
///
/// Order is Linux's and is load-bearing:
///   1. `if (signr == 0) return 0` — cancellation wins over everything, so a
///      tracer can drop a signal that is blocked or fatal-pending.
///   2. rebuild the siginfo when the number changed.
///   3. `if (sigismember(&current->blocked, signr) || fatal_signal_pending())`
///      re-post and report nothing. The block test uses the mask as it stands
///      NOW, not as it stood at dequeue: the tracer may have changed it with
///      `PTRACE_SETSIGMASK` while we were stopped.
/// # C: O(1)
pub fn after_stop(reported: u32, resume_sig: u32, blocked: u64, fatal_pending: bool)
    -> Outcome
{
    if resume_sig == 0 { return Outcome::Suppress; }
    let substituted = resume_sig != reported;
    if fatal_pending || is_blocked(resume_sig, blocked) {
        return Outcome::Requeue { sig: resume_sig };
    }
    Outcome::Deliver { sig: resume_sig, substituted }
}

/// `sigismember(&current->blocked, signr)`. SIGKILL and SIGSTOP are never
/// blockable, so they can never take the requeue arm — a tracer that
/// substitutes SIGSTOP into a masked tracee still stops it.
/// # C: O(1)
pub fn is_blocked(sig: u32, blocked: u64) -> bool {
    if sched::signum::is_unblockable(sig) { return false; }
    match sched::signum::bit_for(sig) { Some(b) => blocked & b != 0, None => false }
}

#[cfg(test)]
#[path = "sigstop/tests.rs"] mod tests;
