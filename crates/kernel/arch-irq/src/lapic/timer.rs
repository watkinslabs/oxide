use core::sync::atomic::Ordering;

use super::regs::{LAPIC_BASE_VA, REG_LVT_TIMER, REG_TIMER_CUR, REG_TIMER_DIV, REG_TIMER_INIT};

const TIMER_VECTOR: u32 = hal_x86_64::VEC_TIMER as u32;
const LVT_MODE_DEADLINE: u32 = 2 << 17;

/// Disarm the LAPIC timer (write 0 to the Initial Count reg).
/// # SAFETY: `enable` ran; LAPIC mapped Device-attr.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn timer_disarm() {
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return; }
    // SAFETY: per fn contract; offset 0x380 within the LAPIC page.
    unsafe { core::ptr::write_volatile((va + REG_TIMER_INIT as u64) as *mut u32, 0); }
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
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return false; }
    // SAFETY: per fn contract -- LAPIC was mapped Device-attr; offsets within the 4 KiB page.
    unsafe {
        core::ptr::write_volatile((va + REG_TIMER_DIV  as u64) as *mut u32, 0b1011);
        core::ptr::write_volatile((va + REG_LVT_TIMER as u64) as *mut u32, 0x40 | (1 << 17));
        core::ptr::write_volatile((va + REG_TIMER_INIT as u64) as *mut u32, initial_count);
    }
    true
}

/// Select TSC-deadline delivery for this CPU's installed timer vector. # C: O(1)
/// # SAFETY: LAPIC is enabled and caller owns this CPU's timer LVT.
/// # Ctx: local CPU, IRQ-off or timer IRQ
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn timer_deadline_mode() -> bool {
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return false; }
    // SAFETY: enabled LAPIC page is mapped Device-attr; LVT/INIT offsets are in-page.
    unsafe {
        core::ptr::write_volatile((va + REG_TIMER_INIT as u64) as *mut u32, 0);
        core::ptr::write_volatile((va + REG_LVT_TIMER as u64) as *mut u32,
            TIMER_VECTOR | LVT_MODE_DEADLINE);
    }
    true
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
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return None; }
    // SAFETY: LAPIC was previously mapped Device-attr; `va` lives
    // inside that 4 KiB page.
    let (a, b) = unsafe {
        // Divide config: `1011` = divide-by-1 (full bus rate).
        core::ptr::write_volatile((va + REG_TIMER_DIV  as u64) as *mut u32, 0b1011);
        // Mask LVT timer (bit 16 = 1) -- no IRQ delivery; just count.
        // Vector 0x40 is set so when we later unmask, it has a valid value.
        core::ptr::write_volatile((va + REG_LVT_TIMER as u64) as *mut u32, 0x40 | (1 << 16));
        // Load initial count -- the timer starts decrementing.
        core::ptr::write_volatile((va + REG_TIMER_INIT as u64) as *mut u32, initial_count);
        let a = core::ptr::read_volatile((va + REG_TIMER_CUR as u64) as *const u32);
        // Brief busy spin so the count visibly decreases.
        for _ in 0..1024 { core::hint::spin_loop(); }
        let b = core::ptr::read_volatile((va + REG_TIMER_CUR as u64) as *const u32);
        // Stop the timer (initial count = 0 disables one-shot).
        core::ptr::write_volatile((va + REG_TIMER_INIT as u64) as *mut u32, 0);
        (a, b)
    };
    Some((a, b))
}
