// ARM virtual generic-timer polled smoke + IRQ-driven periodic.
//
// `timer_smoke` programs CNTV_TVAL_EL0, asserts ENABLE + IMASK in
// CNTV_CTL_EL0 (no IRQ delivery), busy-spins, and reads TVAL again
// to confirm the countdown engine is alive.
// `timer_periodic` programs CNTV_TVAL_EL0 + asserts ENABLE with
// IMASK clear so the line is delivered via GIC INTID 27; the IRQ
// dispatcher reloads TVAL each tick to re-arm the next period.

#[cfg(target_arch = "aarch64")]
use core::sync::atomic::{AtomicU32, Ordering};

/// Per-CPU period (in CNTVCT ticks) used by the IRQ handler to reload
/// CNTV_TVAL_EL0. `0` means this CPU is in one-shot mode.
#[cfg(target_arch = "aarch64")]
static PERIOD: [AtomicU32; cpu::MAX_CPUS] =
    [const { AtomicU32::new(0) }; cpu::MAX_CPUS];

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
fn period_slot() -> &'static AtomicU32 {
    use hal::CpuOps;
    let cpu = crate::ArmCpuOps::current_cpu() as usize;
    PERIOD.get(cpu).unwrap_or(&PERIOD[0])
}

/// Current CPU's periodic reload value, or zero in one-shot mode. # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub fn period() -> u32 { period_slot().load(Ordering::Relaxed) }

/// Set current CPU's periodic reload value. # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub(crate) fn set_period(period: u32) { period_slot().store(period, Ordering::Relaxed); }

const CNTKCTL_EL0PCTEN: u64 = 1 << 0;
const CNTKCTL_EL0VCTEN: u64 = 1 << 1;
const CNTKCTL_EL0_COUNTER_ACCESS: u64 = CNTKCTL_EL0PCTEN | CNTKCTL_EL0VCTEN;

/// Enable EL0 reads of the architected physical/virtual counter.
///
/// # SAFETY: privileged sysreg RMW on this PE; caller runs during CPU
/// bring-up before untrusted EL0 code executes on that PE.
/// # C: O(1)
/// # Ctx: CPU bring-up, IRQ-off
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn enable_el0_counter_access() {
    // SAFETY: CNTKCTL_EL1 is this PE's EL1 timer-control register; RMW only sets Linux-compatible EL0 counter read enable bits.
    unsafe {
        core::arch::asm!(
            "mrs x9, cntkctl_el1",
            "orr x9, x9, {mask}",
            "msr cntkctl_el1, x9",
            "isb",
            mask = in(reg) CNTKCTL_EL0_COUNTER_ACCESS,
            out("x9") _,
            options(nomem, nostack, preserves_flags),
        );
    }
}

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

/// Arm the virtual generic-timer in IRQ-driven periodic-ish mode:
/// load TVAL = `period`, then set CTL = ENABLE | !IMASK so the line
/// is delivered to GIC INTID 27. The IRQ handler reloads TVAL each
/// tick (single-shot retriggered) to produce a periodic stream.
///
/// # SAFETY: CNTV_CTL_EL0 / CNTV_TVAL_EL0 are unprivileged at EL1;
/// no memory effects. Caller must have enabled GIC + INTID 27 first
/// or the line will assert with no consumer.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn timer_periodic(period: u32) {
    set_period(period);
    // SAFETY: per fn contract — sysreg writes legal at EL1, no memory effect; ENABLE=1 IMASK=0 ISTATUS=ignored on write.
    unsafe {
        // Disable while reprogramming.
        let off: u64 = 0;
        core::arch::asm!("msr cntv_ctl_el0, {c}", c = in(reg) off, options(nomem, nostack, preserves_flags));
        let p: u64 = period as u64;
        core::arch::asm!("msr cntv_tval_el0, {v:x}", v = in(reg) p, options(nomem, nostack, preserves_flags));
        // ENABLE=1, IMASK=0.
        let on: u64 = 0b01;
        core::arch::asm!("msr cntv_ctl_el0, {c}", c = in(reg) on, options(nomem, nostack, preserves_flags));
    }
}
