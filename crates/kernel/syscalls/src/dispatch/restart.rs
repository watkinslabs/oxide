// Arch application of Linux's syscall-restart decision at the syscall-return
// tail. The DECISION (which ERESTART* code restarts, under which handler
// state) is owned by `syscall::restart::signal_restart_action` and hosted-
// tested there; this module only rewrites the saved user frame.

#![cfg(target_os = "oxide-kernel")]

use syscall::restart::RestartAction;

/// Apply `action` to the current task's saved user frame. Returns `Some(rv)`
/// when the frame was rewritten to re-enter a syscall — the caller must return
/// that value immediately as the dispatcher retval (it seeds the syscall-number
/// register the re-executed `syscall`/`svc` instruction reads). `None` means
/// nothing was rewritten and the ordinary return path applies.
///
/// Linux `arch_do_signal_or_restart`: `RestartSame` is `regs->ax = orig_ax;
/// regs->ip -= 2`, `RestartBlockCall` is the same rewind with
/// `regs->ax = get_nr_restart_syscall(regs)`.
/// # SAFETY: syscall-return tail; the current task's saved frame is live and
/// exclusively owned by this CPU for the duration of the call.
/// # C: O(1)
pub unsafe fn apply(action: RestartAction) -> Option<u64> {
    match action {
        RestartAction::None | RestartAction::Eintr => None,
        // SAFETY: forwarded contract — caller is the syscall-return tail.
        RestartAction::RestartSame => unsafe { restart_same() },
        // SAFETY: forwarded contract — caller is the syscall-return tail.
        RestartAction::RestartBlockCall => unsafe { restart_block_call() },
    }
}

/// # SAFETY: syscall-return tail owns the current task's saved frame.
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
unsafe fn restart_same() -> Option<u64> {
    // SAFETY: syscall-return tail exclusively owns the current task's syscall-save frame.
    Some(unsafe { hal_x86_64::restart_ignored_syscall() })
}

/// # SAFETY: syscall-return tail owns the current task's saved frame.
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
unsafe fn restart_block_call() -> Option<u64> {
    // SAFETY: syscall-return tail exclusively owns the current task's syscall-save frame.
    Some(unsafe { hal_x86_64::restart_via_restart_syscall(syscall::nrs::NR_RESTART_SYSCALL) })
}

/// The per-task SVC frame the arm64 epilogue restores from, or null before the
/// task's first syscall.
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
fn svc_frame() -> *mut hal_aarch64::SvcFrame {
    use core::sync::atomic::Ordering;
    match sched::live::current() {
        Some(cur) => cur.svc_frame.load(Ordering::Acquire) as *mut hal_aarch64::SvcFrame,
        None => core::ptr::null_mut(),
    }
}

/// # SAFETY: syscall-return tail owns the current task's saved frame.
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
unsafe fn restart_same() -> Option<u64> {
    let frame = svc_frame();
    if frame.is_null() { return None; }
    // SAFETY: syscall-return tail exclusively owns the current task's SVC frame.
    Some(unsafe { hal_aarch64::restart_ignored_syscall(frame) })
}

/// # SAFETY: syscall-return tail owns the current task's saved frame.
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
unsafe fn restart_block_call() -> Option<u64> {
    let frame = svc_frame();
    if frame.is_null() { return None; }
    // SAFETY: syscall-return tail exclusively owns the current task's SVC frame.
    Some(unsafe {
        hal_aarch64::restart_via_restart_syscall(
            frame, syscall::arm_abi::AARCH64_NR_RESTART_SYSCALL)
    })
}
