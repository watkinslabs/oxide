// Arch application of Linux's syscall-restart decision at the syscall-return
// tail. The DECISION (which ERESTART* code restarts, under which handler
// state) is owned by `syscall::restart::signal_restart_action` and hosted-
// tested there; this module only rewrites the saved user frame.

#![cfg(target_os = "oxide-kernel")]

use syscall::restart::RestartAction;
use crate::arch_frame::UserRegs;

/// Apply `action` to the current task's saved user frame. Returns `Some(rv)`
/// when the frame was rewritten to re-enter a syscall — the caller must return
/// that value immediately as the dispatcher retval (it seeds the syscall-number
/// register the re-executed `syscall`/`svc` instruction reads). `None` means
/// nothing was rewritten and the ordinary return path applies.
///
/// Linux `arch_do_signal_or_restart`: `RestartSame` is `regs->ax = orig_ax;
/// regs->ip -= 2`, `RestartBlockCall` is the same rewind with
/// `regs->ax = get_nr_restart_syscall(regs)`.
/// # SAFETY: syscall-return tail; `regs` is that dispatch's live entry frame,
/// exclusively owned by this CPU for the duration of the call.
/// # C: O(1)
pub unsafe fn apply(regs: *mut UserRegs, action: RestartAction) -> Option<u64> {
    if regs.is_null() { return None; }
    match action {
        RestartAction::None | RestartAction::Eintr => None,
        // SAFETY: forwarded contract — caller is the syscall-return tail.
        RestartAction::RestartSame => unsafe { restart_same(regs) },
        // SAFETY: forwarded contract — caller is the syscall-return tail.
        RestartAction::RestartBlockCall => unsafe { restart_block_call(regs) },
    }
}

/// # SAFETY: syscall-return tail owns the current task's saved frame.
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
unsafe fn restart_same(regs: *mut UserRegs) -> Option<u64> {
    // SAFETY: forwarded contract — `regs` is the live entry frame.
    Some(unsafe { hal_x86_64::restart_ignored_syscall(regs) })
}

/// # SAFETY: syscall-return tail owns the current task's saved frame.
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
unsafe fn restart_block_call(regs: *mut UserRegs) -> Option<u64> {
    // SAFETY: forwarded contract — `regs` is the live entry frame.
    Some(unsafe { hal_x86_64::restart_via_restart_syscall(regs, syscall::nrs::NR_RESTART_SYSCALL) })
}

/// # SAFETY: syscall-return tail owns `regs`, its live entry frame.
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
unsafe fn restart_same(regs: *mut UserRegs) -> Option<u64> {
    // SAFETY: forwarded contract — `regs` is the live entry frame.
    Some(unsafe { hal_aarch64::restart_ignored_syscall(regs) })
}

/// # SAFETY: syscall-return tail owns `regs`, its live entry frame.
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
unsafe fn restart_block_call(regs: *mut UserRegs) -> Option<u64> {
    // SAFETY: forwarded contract — `regs` is the live entry frame.
    Some(unsafe {
        hal_aarch64::restart_via_restart_syscall(
            regs, syscall::arm_abi::AARCH64_NR_RESTART_SYSCALL)
    })
}
