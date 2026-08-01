// Linux `arch_do_signal_or_restart(regs)` (`arch/x86/kernel/signal.c`,
// `arch/arm64/kernel/signal.c`): dequeue one signal, deliver it, and apply the
// syscall-restart decision. Called from the ONE return-to-user work loop, so
// an IRQ or exception return reaches exactly the same body a syscall return
// does — the point of B1471.
//
// Moved out of `dispatch/core.rs`, which used to be the only caller and the
// only return path with any signal check at all.

#![cfg(target_os = "oxide-kernel")]

use sched::signum::Signum;
use syscall::restart::RestartAction;
use super::UserRegs;

/// Linux `restore_saved_sigmask()`: a `rt_sigsuspend`/`pselect6`-style
/// temporary mask is put back on the way to userspace, but ONLY when no
/// handler ran — a handler must execute under the temporary mask and let
/// `rt_sigreturn` restore the saved one from its frame. One-shot: the flag is
/// consumed by whichever path gets there first.
/// # C: O(1)
#[inline]
fn restore_saved_sigmask() {
    if let Some(cur) = sched::live::current() { cur.restore_saved_sigmask(); }
}

/// SIG_DFL sentinel (Linux uapi `sa_handler` convention).
const SIG_DFL: u64 = 0;

/// Whether this dequeued signal takes the job-control stop arm rather than
/// building a handler frame: SIGSTOP always (uncatchable), and
/// SIGTSTP/SIGTTIN/SIGTTOU only while their disposition is still SIG_DFL.
/// # C: O(1)
fn takes_jobctl_stop(sig: u32, handler: u64) -> bool {
    if sig == Signum::Sigstop as u32 { return true; }
    let jobctl = sig == Signum::Sigtstp as u32
        || sig == Signum::Sigttin as u32
        || sig == Signum::Sigttou as u32;
    jobctl && handler == SIG_DFL
}

/// Result of one `arch_do_signal_or_restart` call.
pub struct Outcome {
    /// The interrupted syscall's return value after the restart decision.
    pub rv:   i64,
    /// aarch64 only: the value the SVC epilogue loads into user x0 (the
    /// handler's first AAPCS64 argument), which it takes from the dispatcher's
    /// return rather than from the frame's x0 slot. `None` on every path that
    /// built no handler frame, and always `None` on x86_64 (rdi is seeded in
    /// the frame itself).
    pub arch_retval: Option<u64>,
}

/// One `arch_do_signal_or_restart` call. `rv` is the interrupted syscall's
/// return value and `from_syscall` Linux's `syscall_get_nr(regs) != -1` —
/// false on an interrupt or exception return, where there is no interrupted
/// syscall to restart and the return-value register holds an ordinary user
/// value that must not be rewritten.
///
/// # SAFETY: caller is the return-to-user work loop on the running task's own
/// kernel stack; `regs` is that return's live entry frame.
/// # C: O(1)
/// # Ctx: return-to-user, interrupts enabled
/// # Sleeps: yes — a job-control stop parks, and a faulting frame write can
pub unsafe fn do_signal_or_restart(regs: *mut UserRegs, rv: i64, from_syscall: bool) -> Outcome {
    let Some(p) = crate::signal::take_lowest_pending() else {
        // Linux `arch_do_signal_or_restart` with `get_signal()` returning 0:
        // the interrupting signal was consumed elsewhere (group-exit latch,
        // stop/cont, a racing dequeue), so the interrupted call restarts. A
        // blocking syscall only emits ERESTART* when a deliverable signal
        // existed, and `take_lowest_pending` clears the pending bit before the
        // restart, so this cannot spin.
        debug_ssh! { crate::signal_trace::deliver_blocked(); }
        restore_saved_sigmask();
        // SAFETY: forwarded contract — `regs` is the live entry frame.
        return unsafe { no_handler_restart(regs, rv, from_syscall) };
    };
    debug_ssh! { crate::signal_trace::deliver_taken(&p); }
    #[cfg(feature = "debug-zram-lifecycle")]
    crate::signal_trace::zram_lifecycle_deliver(&p);
    // Linux `get_signal`: the ptrace arm sits BETWEEN `dequeue_signal` and the
    // disposition switch, so the tracer sees the signal before any handler,
    // SIG_IGN or job-control stop acts on it — and whatever it names on resume
    // is what the switch below then acts on.
    let p = match ptrace_signal(p) {
        Some(p) => p,
        // `if (!signr) continue;` — the tracer cancelled it, or it had to be
        // re-posted. Nothing is delivered on this pass; the return-to-user work
        // loop re-reads the pending set and dequeues the next signal, which is
        // what Linux's `continue` does inside `get_signal`'s own loop.
        None => {
            restore_saved_sigmask();
            // SAFETY: forwarded contract — `regs` is the live entry frame.
            return unsafe { no_handler_restart(regs, rv, from_syscall) };
        }
    };
    if takes_jobctl_stop(p.sig, p.handler) {
        restore_saved_sigmask();
        sched::live::stop::stop_until_cont_sig(p.sig as u8);
        // A job-control stop builds NO handler frame, so Linux's
        // `arch_do_signal_or_restart` arm applies once the task resumes:
        // every ERESTART* code restarts, ERESTART_RESTARTBLOCK through
        // `restart_syscall(2)`. Returning the raw `rv` here would leak the
        // internal -512/-514/-516 sentinels to userspace as bogus errnos.
        // SAFETY: forwarded contract — the live entry frame is owned here.
        return unsafe { no_handler_restart(regs, rv, from_syscall) };
    }
    // Linux's restart decision (`handle_signal` vs `arch_do_signal_or_restart`)
    // keys on whether a HANDLER FRAME was actually built. SIG_DFL and SIG_IGN
    // dispositions take the no-handler arm, which restarts every ERESTART* code
    // instead of reporting a spurious EINTR.
    let handler_ran = crate::signal::runs_user_handler(&p);
    let sa_restart = (p.flags & crate::signal_dispatch::SA_RESTART) != 0;
    let action = if from_syscall {
        syscall::restart::signal_restart_action(rv, handler_ran, sa_restart)
    } else {
        RestartAction::None
    };
    // SAFETY: forwarded contract — `regs` is the live entry frame; the builder
    // rewrites only that frame and the user signal stack.
    let sig_rv = unsafe { crate::signal_dispatch::dispatch_pending(regs, &p, rv as u64, from_syscall) };
    // Linux `restore_saved_sigmask()` on the no-handler exits. A handler
    // delivery already consumed the flag inside `sigmask_to_save()` and folded
    // the saved mask into the frame `rt_sigreturn` restores, so this is a no-op
    // there — the flag is one-shot.
    restore_saved_sigmask();
    if handler_ran {
        // The frame `rt_sigreturn` restores now carries the post-decision
        // return value (`frame_user_return` inside `dispatch_pending`), so a
        // FURTHER signal delivered by a later pass of this loop must see that
        // value, not the consumed ERESTART* sentinel.
        let restarted = action == RestartAction::RestartSame;
        return Outcome {
            rv: syscall::restart::frame_user_return(rv, restarted),
            arch_retval: if sig_rv != 0 { Some(sig_rv) } else { None },
        };
    }
    // No handler frame: SIG_DFL / SIG_IGN. `dispatch_pending` may not return at
    // all here (a fatal default action exits the thread group).
    // SAFETY: forwarded contract — the live entry frame is owned here.
    unsafe { no_handler_restart(regs, rv, from_syscall) }
}

/// Linux `get_signal`'s ptrace arm plus `ptrace_signal`.
///
/// Fast path: one relaxed-ordering read of `traced_by`. An untraced task —
/// every task on a normal system — allocates nothing and takes one
/// never-taken branch, which is why the whole thing is behind a single
/// `stops_for_tracer` test rather than a call.
///
/// `None` = deliver nothing this pass (the tracer cancelled the signal, or it
/// was re-posted because it is now blocked or the task is dying).
/// # Sleeps: yes when the task is traced — it parks in the stop.
/// # C: O(1) untraced; O(N_schedule) traced
fn ptrace_signal(p: crate::signal::PendingSignal) -> Option<crate::signal::PendingSignal> {
    use core::sync::atomic::Ordering;
    let Some(cur) = sched::live::current() else { return Some(p) };
    let traced = cur.traced_by.load(Ordering::Relaxed) != 0;
    let immutable = cur.sigactions_ref().is_immutable(p.sig);
    if !crate::s101_ptrace_sigstop::stops_for_tracer(traced, p.sig, immutable) { return Some(p); }
    let (outcome, info) = crate::ptrace::stop::signal_stop(p.sig, p.info);
    match outcome {
        crate::s101_ptrace_sigstop::Outcome::Suppress => None,
        crate::s101_ptrace_sigstop::Outcome::Requeue { sig } => {
            // `send_signal_locked(signr, info, current, type)` — the signal is
            // not lost, it is put back for a pass on which it is deliverable.
            let src = match info {
                Some(i) => sched::sigsend::SigSource::Info(i),
                None => sched::sigsend::SigSource::Kernel,
            };
            sched::live::send_sig_self_info(sig, src);
            None
        }
        // The disposition must be re-read for a SUBSTITUTED signal: the
        // handler, flags, sa_mask and restorer of the signal the tracer named
        // are what runs, not those of the one the tracee reported.
        crate::s101_ptrace_sigstop::Outcome::Deliver { sig, substituted } => {
            if !substituted { return Some(crate::signal::PendingSignal { info, ..p }); }
            Some(crate::signal::pending_for(sig, info))
        }
    }
}

/// Linux `arch_do_signal_or_restart`'s no-handler tail: apply the restart
/// action to the live frame, or normalize the sentinel away.
/// # SAFETY: `regs` is the caller's live entry frame.
/// # C: O(1)
unsafe fn no_handler_restart(regs: *mut UserRegs, rv: i64, from_syscall: bool) -> Outcome {
    if !from_syscall { return Outcome { rv, arch_retval: None }; }
    let action = syscall::restart::signal_restart_action(rv, false, false);
    // SAFETY: forwarded contract — the live entry frame is owned by this pass.
    if let Some(re) = unsafe { crate::dispatch::restart::apply(regs, action) } {
        // The frame was rewritten to re-enter a syscall; `re` seeds the
        // syscall-number register the re-executed instruction reads, so it must
        // reach the dispatcher's return slot unmodified.
        return Outcome { rv: re as i64, arch_retval: Some(re) };
    }
    Outcome { rv: syscall::restart::normalize_user_return(rv), arch_retval: None }
}
