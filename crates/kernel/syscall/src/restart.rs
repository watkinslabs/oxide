// Linux internal syscall-restart return codes (`include/linux/errno.h`) plus
// the signal-delivery-time restart decision Linux's `arch_do_signal_or_restart`
// / `handle_signal` make from them. These codes are not errno values and must
// never escape to userspace.
//
// Module manifest:
// - this file: ERESTART* encodings, `RestartAction`, `signal_restart_action`.
// - `restart/tests.rs`: hosted table tests for both.

use crate::Errno;

/// Linux `ERESTARTSYS`: restart a signal-interrupted blocking syscall only
/// when the delivered handler opted into `SA_RESTART`; otherwise expose EINTR.
pub const ERESTARTSYS: i64 = 512;
/// Linux `ERESTARTNOINTR`: restart unconditionally — the call is not allowed
/// to be observed as interrupted (fork/clone rollback, sigreturn repair).
pub const ERESTARTNOINTR: i64 = 513;
/// Linux `ERESTARTNOHAND`: restart only when NO user handler ran; a handler
/// delivery turns it into EINTR.
pub const ERESTARTNOHAND: i64 = 514;
/// Linux `ERESTART_RESTARTBLOCK`: resume through `restart_syscall(2)` and the
/// task's `restart_block`; a handler delivery turns it into EINTR.
pub const ERESTART_RESTARTBLOCK: i64 = 516;

/// Encode an internal restart code as a negative syscall return.
/// # C: O(1)
pub const fn restart_nohand() -> i64 { -ERESTARTNOHAND }

/// Encode Linux's handler-controlled restart request. # C: O(1)
pub const fn restart_sys() -> i64 { -ERESTARTSYS }

/// Encode Linux's unconditional restart request. # C: O(1)
pub const fn restart_nointr() -> i64 { -ERESTARTNOINTR }

/// True when `rv` is Linux's handler-controlled restart sentinel.
/// # C: O(1)
pub const fn is_restart_sys(rv: i64) -> bool { rv == restart_sys() }

/// Encode an internal restart-block return.
/// # C: O(1)
pub const fn restart_block() -> i64 { -ERESTART_RESTARTBLOCK }

/// True when `rv` is any ERESTART* sentinel rather than a real result/errno.
/// # C: O(1)
pub const fn is_restart_code(rv: i64) -> bool {
    rv == restart_sys() || rv == restart_nointr()
        || rv == restart_nohand() || rv == restart_block()
}

/// What the syscall-return tail must do with an ERESTART* sentinel, per
/// Linux `arch/x86/kernel/signal.c` `handle_signal` (a handler was set up) and
/// `arch_do_signal_or_restart` (no handler ran).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RestartAction {
    /// `rv` is an ordinary result/errno — return it untouched.
    None,
    /// Rewind the user PC and re-enter the SAME syscall number.
    RestartSame,
    /// Rewind the user PC and re-enter as `restart_syscall(2)`, which resumes
    /// through `current->restart_block`.
    RestartBlockCall,
    /// Report EINTR to userspace.
    Eintr,
}

/// Linux's restart decision. `handler_ran` is true only when a user handler
/// frame was actually built (`get_signal` returned a caught signal);
/// SIG_DFL/SIG_IGN dispositions and "no signal at all" are both `false`.
/// `sa_restart` is the delivered handler's `SA_RESTART` bit.
///
/// Handler path (`handle_signal`): ERESTART_RESTARTBLOCK and ERESTARTNOHAND
/// collapse to EINTR, ERESTARTSYS restarts only under SA_RESTART, and
/// ERESTARTNOINTR always restarts. No-handler path
/// (`arch_do_signal_or_restart`): ERESTARTNOHAND / ERESTARTSYS / ERESTARTNOINTR
/// restart the same call, ERESTART_RESTARTBLOCK becomes `restart_syscall(2)`.
/// # C: O(1)
pub const fn signal_restart_action(rv: i64, handler_ran: bool, sa_restart: bool) -> RestartAction {
    if !is_restart_code(rv) { return RestartAction::None; }
    if handler_ran {
        if rv == restart_nointr() { return RestartAction::RestartSame; }
        if rv == restart_sys() {
            return if sa_restart { RestartAction::RestartSame } else { RestartAction::Eintr };
        }
        // ERESTARTNOHAND / ERESTART_RESTARTBLOCK
        RestartAction::Eintr
    } else {
        if rv == restart_block() { return RestartAction::RestartBlockCall; }
        RestartAction::RestartSame
    }
}

/// The value Linux's `handle_signal` leaves in the syscall-return register of
/// the frame `rt_sigreturn` restores. When the call is being restarted the
/// register carries the syscall number (`regs->ax = regs->orig_ax`), so the
/// raw `rv` is right; otherwise Linux writes `regs->ax = -EINTR` EXPLICITLY
/// (`arch/x86/kernel/signal.c` `handle_signal`, `arch/arm64/kernel/signal.c`
/// `handle_signal`) — the internal ERESTART* sentinel must never reach the
/// frame, because `rt_sigreturn` puts it straight into userspace.
///
/// B1448: both HALs stored the raw `saved_ret` here, so an interrupted
/// syscall whose handler did not opt into `SA_RESTART` returned the
/// sentinel (-512/-514/-516) instead of EINTR. `normalize_user_return` was
/// applied only to the DISPATCHER's return value, which the restored frame
/// then overwrote.
/// # C: O(1)
pub const fn frame_user_return(rv: i64, restart: bool) -> i64 {
    if restart { rv } else { normalize_user_return(rv) }
}

/// Linux gates EVERY arm of `arch_do_signal_or_restart` on `in_syscall(regs)`
/// (`arch/arm64/kernel/signal.c:1631` + `:1636`; x86's `orig_ax` test), and
/// `rt_sigreturn` deliberately leaves that gate CLOSED: arm64
/// `restore_sigframe` calls `forget_syscall(regs)` — "Avoid sys_rt_sigreturn()
/// restarting" (`arch/arm64/kernel/signal.c:1032-1035`, `regs->syscallno =
/// NO_SYSCALL`) — and x86_64 `restore_sigcontext` sets `regs->orig_ax = -1`
/// — "disable syscall checks" (`arch/x86/kernel/signal_64.c:85-86`).
///
/// The frame `rt_sigreturn` restores is a HANDLER's saved user context, not a
/// syscall frame, and both HALs have already overwritten the saved
/// syscall-number slot (x86 `rax`) / first-argument slot (arm64 `x0`) from the
/// ucontext. Re-entering from there runs the `syscall`/`svc` with garbage: an
/// invalid syscall number on x86_64 (ENOSYS) and a garbage first argument on
/// aarch64 (EINVAL/EBADF). That is exactly the arch-divergent shape the F753
/// guest differential recorded before B1448 stopped the ERESTART* sentinel
/// reaching the frame at all; this gate closes the mechanism itself, so the
/// class cannot come back through any other value the ucontext carries.
/// # C: O(1)
pub const fn syscall_restart_allowed(nr: u64) -> bool { nr != crate::nrs::NR_RT_SIGRETURN }

/// Convert internal restart codes to the userspace-visible Linux errno. Only
/// reached once the restart decision above declined to restart, so it is the
/// EINTR arm of `signal_restart_action`.
/// # C: O(1)
pub const fn normalize_user_return(rv: i64) -> i64 {
    if is_restart_code(rv) { -(Errno::Eintr.as_i32() as i64) } else { rv }
}

#[cfg(test)]
#[path = "restart/tests.rs"]
mod tests;
