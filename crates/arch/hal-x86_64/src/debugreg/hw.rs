// Hardware DR0-DR3/DR6/DR7 access. Gated to the kernel target exactly as the
// privileged-register helpers in `regs.rs` are; every caller above this file
// works on the `DebugRegs` value type instead.

use core::arch::asm;

use super::state::DebugRegs;

/// Write DR0-DR3 then DR7 from a task's shadow state. DR6 is a status
/// register and is deliberately not restored: hardware owns it and the task's
/// copy is refreshed from `store_dr6` at trap time.
/// # SAFETY: caller must be at CPL=0 and must own this CPU's debug registers
/// for the duration (no concurrent diagnostic watchpoint arming).
/// # C: O(1)
pub unsafe fn load(regs: &DebugRegs) {
    // SAFETY: `mov drN, r` is privileged and legal at CPL=0 with no memory
    // effects. DR7 is written last so no slot is ever enabled against a stale
    // address. Per fn contract this CPU's debug registers are caller-owned.
    unsafe {
        asm!("mov dr0, {}", in(reg) regs.addr[0], options(nomem, nostack, preserves_flags));
        asm!("mov dr1, {}", in(reg) regs.addr[1], options(nomem, nostack, preserves_flags));
        asm!("mov dr2, {}", in(reg) regs.addr[2], options(nomem, nostack, preserves_flags));
        asm!("mov dr3, {}", in(reg) regs.addr[3], options(nomem, nostack, preserves_flags));
        asm!("mov dr7, {}", in(reg) regs.hw_dr7(), options(nomem, nostack, preserves_flags));
    }
}

/// Disable every slot without touching the address registers.
/// # SAFETY: caller must be at CPL=0 and own this CPU's debug registers.
/// # C: O(1)
pub unsafe fn disarm() {
    // SAFETY: `mov dr7, r` is privileged, legal at CPL=0, no memory effects.
    // Writing the reset value clears all four enable bits at once, which is
    // the only state change this makes.
    unsafe {
        asm!("mov dr7, {}", in(reg) super::dr7::DR7_EMPTY, options(nomem, nostack, preserves_flags));
    }
}

/// Read DR6 and clear it, returning the cause bits of the #DB just taken.
/// # SAFETY: caller must be at CPL=0 and own this CPU's debug registers.
/// # C: O(1)
pub unsafe fn store_dr6() -> u64 {
    // SAFETY: delegates to the crate's single DR6 read-and-clear asm site;
    // privileged, legal at CPL=0, caller owns this CPU's debug registers per
    // the fn contract above.
    unsafe { crate::regs::read_clear_dr6() }
}

/// Context-switch hook. Skips every debug-register write when neither the
/// outgoing nor the incoming task has a slot armed, which is the common case.
/// # SAFETY: caller must be at CPL=0 on the switching CPU with that CPU's
/// debug registers owned by the scheduler for the duration.
/// # C: O(1)
pub unsafe fn switch(prev: &DebugRegs, next: &DebugRegs) {
    if !prev.is_armed() && !next.is_armed() { return; }
    // SAFETY: reached only when one side is armed; `load` carries the same
    // CPL=0 / caller-owns-the-debug-registers contract as this fn.
    unsafe { load(next); }
}
