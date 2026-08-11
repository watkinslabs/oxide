use super::regs::{read_register, write_register, REG_LVT_TIMER, REG_TIMER_CUR, REG_TIMER_DIV, REG_TIMER_INIT};

const TIMER_VECTOR: u32 = hal_x86_64::VEC_TIMER as u32;
const LVT_MODE_DEADLINE: u32 = 2 << 17;

/// Disarm the LAPIC timer (write 0 to the Initial Count reg).
/// # SAFETY: `enable` ran; LAPIC mapped Device-attr.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn timer_disarm() {
    // SAFETY: caller owns this enabled LAPIC timer register transition.
    let _ = unsafe { write_register(REG_TIMER_INIT, 0) };
}

/// Configure the LAPIC timer in periodic mode unmasked at vector
/// 0x40. Caller must have wired IDT[0x40] to an IRQ stub (the
/// default `install_default_idt` does) and must `sti` afterwards
/// to actually receive ticks.
///
/// # SAFETY: `enable` has run; LAPIC is mapped + software-enabled.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn timer_periodic(initial_count: u32) -> bool {
    // SAFETY: caller owns this enabled LAPIC timer register transition.
    unsafe { write_register(REG_TIMER_DIV, 0b1011)
        && write_register(REG_LVT_TIMER, 0x40 | (1 << 17))
        && write_register(REG_TIMER_INIT, initial_count) }
}

/// Select TSC-deadline delivery for this CPU's installed timer vector. # C: O(1)
/// # SAFETY: LAPIC is enabled and caller owns this CPU's timer LVT.
/// # Ctx: local CPU, IRQ-off or timer IRQ
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn timer_deadline_mode() -> bool {
    // SAFETY: caller owns this enabled LAPIC timer register transition.
    unsafe { write_register(REG_TIMER_INIT, 0)
        && write_register(REG_LVT_TIMER, TIMER_VECTOR | LVT_MODE_DEADLINE) }
}

/// Configure the LAPIC timer in one-shot mode, masked (no IRQ
/// delivery yet -- this is purely a hardware-tick smoke). Returns
/// the current count register reading after a brief busy spin so
/// the caller can confirm the counter is decrementing.
///
/// `initial_count` is loaded into the timer's Initial Count
/// Register; with divide=0b1011 (1) the LAPIC bus clock decrements
/// the count register by one per cycle.
///
/// # SAFETY: caller asserts `enable` has run and `LAPIC_BASE_VA`
/// is non-zero. Single-CPU, IRQ-off.
/// # C: O(spin)
/// # Ctx: pre-init, single-CPU
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn timer_smoke(initial_count: u32) -> Option<(u32, u32)> {
    // SAFETY: caller owns this enabled LAPIC timer register transition.
    unsafe {
        if !write_register(REG_TIMER_DIV, 0b1011)
            || !write_register(REG_LVT_TIMER, 0x40 | (1 << 16))
            || !write_register(REG_TIMER_INIT, initial_count) { return None; }
    }
    // SAFETY: the timer current-count register is readable after programming the enabled LAPIC.
    let a = unsafe { read_register(REG_TIMER_CUR) }?;
    for _ in 0..1024 { core::hint::spin_loop(); }
    // SAFETY: same enabled-LAPIC timer-read contract as the first current-count sample.
    let b = unsafe { read_register(REG_TIMER_CUR) }?;
    // SAFETY: caller owns this enabled LAPIC timer register transition.
    let _ = unsafe { write_register(REG_TIMER_INIT, 0) };
    Some((a, b))
}
