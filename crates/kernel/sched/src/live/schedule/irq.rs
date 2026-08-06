// Context-switch IRQ state and bounded idle waits.

/// Mask IRQs for the pick + context switch, returning the exact caller state.
/// Process context normally enters IRQ-on; early boot, exit work and atomic
/// callers can still schedule IRQ-off. Host builds no-op.
/// # SAFETY: caller must pass the returned token once to `restore` after the
/// same task resumes its context-switch frame. # C: O(1)
#[inline]
pub(super) unsafe fn save_disable() -> u64 {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    {
        let flags: u64;
        // SAFETY: reads RFLAGS then masks IRQs; `restore` consumes the token
        // when this task resumes from its own context switch.
        unsafe { core::arch::asm!("pushfq", "pop {f}", "cli", f = out(reg) flags, options(nomem, preserves_flags)); }
        flags
    }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    {
        let flags: u64;
        // SAFETY: reads DAIF then masks IRQs; `restore` consumes the token when
        // this task resumes from its own context switch.
        unsafe { core::arch::asm!("mrs {f}, daif", "msr daifset, #2", f = out(reg) flags, options(nomem, nostack, preserves_flags)); }
        flags
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Restore the exact IRQ state captured by `save_disable`.
/// # SAFETY: `flags` is the unmatched token from this task's `save_disable`.
/// # C: O(1)
#[inline]
pub(super) unsafe fn restore(flags: u64) {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    // SAFETY: token came from this task's matching `save_disable` call.
    unsafe { core::arch::asm!("push {f}", "popfq", f = in(reg) flags, options(nomem)); }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    // SAFETY: token came from this task's matching `save_disable` call.
    unsafe { core::arch::asm!("msr daif, {f}", f = in(reg) flags, options(nomem, nostack, preserves_flags)); }
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = flags; }
}

/// Open one idle instruction with IRQ delivery enabled, restoring the exact
/// caller state afterwards.
/// # SAFETY: caller is process or idle context with no lock held.
/// # C: O(1)
#[inline]
pub(super) unsafe fn halt_enabled() {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    {
        use sync::IrqGate;
        // SAFETY: caller provides a lock-free process/idle window.
        let flags = unsafe { hal_x86_64::X86IrqGate::save_enable() };
        // SAFETY: privileged idle instruction at CPL0 with IRQ delivery live.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)); }
        // SAFETY: token came from the matching gate call in this frame.
        unsafe { hal_x86_64::X86IrqGate::restore(flags); }
    }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    {
        use sync::IrqGate;
        // SAFETY: caller provides a lock-free process/idle window.
        let flags = unsafe { hal_aarch64::ArmIrqGate::save_enable() };
        // SAFETY: privileged idle instruction at EL1 with IRQ delivery live.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)); }
        // SAFETY: token came from the matching gate call in this frame.
        unsafe { hal_aarch64::ArmIrqGate::restore(flags); }
    }
}
