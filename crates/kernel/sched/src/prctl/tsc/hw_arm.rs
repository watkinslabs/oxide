// aarch64: `CNTKCTL_EL1.EL0PCTEN|EL0VCTEN`. Cleared = an EL0 `mrs CNTVCT_EL0`
// traps to EL1 instead of returning the counter.

/// # SAFETY: privileged CNTKCTL_EL1 write, legal at EL1; the register is
/// per-PE so this CPU is its sole writer, and callers run preempt-off.
/// # C: O(1)
pub unsafe fn set_trapped(on: bool) {
    // SAFETY: forwards this fn's own contract — privileged per-PE CNTKCTL_EL1 RMW, preempt-off caller, no other CNTKCTL field touched.
    unsafe { hal_aarch64::timer::set_el0_counter_access(!on) }
}
