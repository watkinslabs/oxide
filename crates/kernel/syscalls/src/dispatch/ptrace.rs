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
/// # C: O(1)
pub(super) fn ptrace_syscall_stop_if_armed(rax: u64, entry: bool) {
    use core::sync::atomic::Ordering;
    use sched::Signum;
    use crate::s101_ptrace_event as event;
    let cur = match sched::live::current() { Some(c) => c, None => return };
    if cur.traced_by.load(Ordering::Acquire) == 0 { return; }
    if !cur.ptrace_syscall_armed.swap(false, Ordering::AcqRel) { return; }
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
}
