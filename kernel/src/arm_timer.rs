// ARM virtual generic-timer polled smoke.
//
// Programs CNTV_TVAL_EL0 with a starting value, asserts ENABLE +
// IMASK in CNTV_CTL_EL0 (no IRQ delivery yet), busy-spins, and
// reads TVAL again to confirm the countdown engine is alive.
// Foundation for the IRQ-driven tick that lands once GIC routing
// + EL1 vector handling are wired.

/// Run a polled smoke and return (before, after) TVAL readings.
/// Returns `None` if the kernel target lacks the timer (host).
///
/// # SAFETY: privileged sysreg writes; legal at EL1 with no memory
/// effects. Single-CPU; no other path is touching the timer.
/// # C: O(spin)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn timer_smoke(initial_tval: u32) -> Option<(u32, u32)> {
    // SAFETY: per fn contract — sysreg reads/writes are EL1-priv
    // but legal; no memory effect, no flag changes.
    unsafe {
        // Mask + disable while we set TVAL; bit 1 = IMASK, bit 0 = ENABLE.
        let ctl_off: u64 = 0b10;  // ENABLE=0, IMASK=1
        core::arch::asm!(
            "msr cntv_ctl_el0, {c}",
            c = in(reg) ctl_off,
            options(nomem, nostack, preserves_flags),
        );
        core::arch::asm!(
            "msr cntv_tval_el0, {v:x}",
            v = in(reg) initial_tval,
            options(nomem, nostack, preserves_flags),
        );
        // ENABLE=1, IMASK=1 — counter runs, no IRQ.
        let ctl_on: u64 = 0b11;
        core::arch::asm!(
            "msr cntv_ctl_el0, {c}",
            c = in(reg) ctl_on,
            options(nomem, nostack, preserves_flags),
        );
        let a: u64;
        core::arch::asm!(
            "mrs {v}, cntv_tval_el0",
            v = out(reg) a,
            options(nomem, nostack, preserves_flags),
        );
        for _ in 0..1024 { core::hint::spin_loop(); }
        let b: u64;
        core::arch::asm!(
            "mrs {v}, cntv_tval_el0",
            v = out(reg) b,
            options(nomem, nostack, preserves_flags),
        );
        // Disable the timer.
        core::arch::asm!(
            "msr cntv_ctl_el0, xzr",
            options(nomem, nostack, preserves_flags),
        );
        Some((a as u32, b as u32))
    }
}
