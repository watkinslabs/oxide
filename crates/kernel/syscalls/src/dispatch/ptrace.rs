#![cfg(target_os = "oxide-kernel")]

/// PTRACE_SYSCALL self-stop. `rax` is the value a tracer's GETREGS must see
/// in the ABI return register at this stop: Linux reports `-ENOSYS` at the
/// syscall-entry stop and the real result at the syscall-exit stop. The saved
/// entry frame keeps the syscall number in that slot, so the value is
/// recorded on the task instead of being reconstructed from the frame.
///
/// `entry` selects the `ptrace_message` the stop records
/// (`PTRACE_EVENTMSG_SYSCALL_ENTRY` / `_EXIT`), which is the ONLY thing that
/// tells `PTRACE_GET_SYSCALL_INFO` whether it is looking at an entry or an
/// exit stop — both carry the same `SIGTRAP | 0x80` si_code.
///
/// One armed request produces exactly ONE stop: `swap(false)` disarms before
/// parking, so a tracer that wants the matching exit stop must issue a second
/// PTRACE_SYSCALL, as Linux requires.
///
/// Returns `fatal_signal_pending` — `ptrace_report_syscall`'s own return, which
/// the entry side turns into "abort the call". A tracee that was killed while
/// stopped must not go on to run the syscall it was stopped on the way into.
/// # C: O(1)
pub(super) fn ptrace_syscall_stop_if_armed(rax: u64, entry: bool) -> bool {
    use core::sync::atomic::Ordering;
    use sched::Signum;
    use crate::s101_ptrace_event as event;
    let cur = match sched::live::current() { Some(c) => c, None => return false };
    if cur.traced_by.load(Ordering::Acquire) == 0 { return false; }
    if !cur.ptrace_syscall_armed.swap(false, Ordering::AcqRel) { return false; }
    cur.ptrace_stop_rax.store(rax, Ordering::Release);
    // Linux `ptrace_report_syscall`: the stop signal reported through
    // wait(2) is `SIGTRAP | 0x80` when PTRACE_O_TRACESYSGOOD is set, which is
    // how a tracer tells a syscall stop from a real SIGTRAP. `ptrace_notify`
    // then stores that same value in `si_code`. Reporting a bare SIGTRAP
    // (what this did) makes strace misclassify every syscall stop.
    let opts = cur.ptrace_options.load(Ordering::Acquire);
    let sysgood = (opts & crate::s101_ptrace_uapi::O_TRACESYSGOOD) != 0;
    let stop_code = Signum::Sigtrap as i32
        | if sysgood { crate::s101_ptrace_uapi::SYSCALL_TRAP_BIT } else { 0 };
    let msg = if entry { event::EVENTMSG_SYSCALL_ENTRY } else { event::EVENTMSG_SYSCALL_EXIT };
    // `ptrace_notify` — records the message, publishes `last_siginfo` and
    // parks. It queues NO signal: a real SIGTRAP posted here would survive
    // the tracer's PTRACE_CONT and kill the tracee with its default action.
    let resume_sig = crate::ptrace::stop::notify(stop_code, msg);
    // `ptrace_report_syscall`'s tail: `if (signr) send_sig(signr, current, 1)`.
    // A syscall stop has no signal to replace, so the tracer's `data` is POSTED
    // — the one stop kind where PTRACE_CONT(sig) genuinely adds a signal. An
    // event stop discards it instead (`ptrace_event` ignores the return), which
    // is why this arm lives here and not inside `notify`.
    if resume_sig != 0 {
        sched::live::send_sig_self_info(resume_sig, sched::sigsend::SigSource::Kernel);
    }
    cur.sigpending.load(Ordering::Acquire) & Signum::Sigkill.bit() != 0
}

/// Re-read the syscall number the entry frame holds NOW.
///
/// A tracer stopped at the entry stop may have rewritten it (and the
/// arguments) with `PTRACE_SETREGS` / `PTRACE_POKEUSER` /
/// `PTRACE_SET_SYSCALL_INFO`. Everything downstream — the seccomp filter and
/// the dispatch itself — must act on what the frame says now, not on what
/// userspace originally asked for, or the rewrite is silently ignored.
/// # C: O(1)
pub(super) fn syscall_nr_after_entry_stop(orig: u64) -> u64 {
    use core::sync::atomic::Ordering;
    // Untraced is the overwhelmingly common case and there is nobody who could
    // have rewritten anything, so the frame read is skipped entirely — one
    // atomic load on the syscall hot path instead.
    match sched::live::current() {
        Some(c) if c.traced_by.load(Ordering::Acquire) != 0 => {}
        _ => return orig,
    }
    let regs = crate::arch_frame::current_user_regs();
    if regs.is_null() { return orig; }
    // SAFETY: `current_user_regs` is this task's own live syscall entry frame on its own kernel stack, read-only, and this task is the sole mutator of it per `13§5`.
    unsafe { crate::arch_frame::frame_syscall_nr(regs) }
}
