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

// OR'd into CNTKCTL_EL1 by `enable_el0_counter_access`. Also read by
// `set_el0_counter_access`, the per-task toggle behind `prctl(PR_SET_TSC)`,
// and by the pure `cntkctl_with_counter_access` below — so the host build
// needs them too and they carry no target gate.
/// CNTKCTL_EL1.EL0PCTEN (bit 0) — EL0 may read `CNTPCT_EL0`.
pub const CNTKCTL_EL0PCTEN: u64 = 1 << 0;
/// CNTKCTL_EL1.EL0VCTEN (bit 1) — EL0 may read `CNTVCT_EL0`/`CNTFRQ_EL0`.
pub const CNTKCTL_EL0VCTEN: u64 = 1 << 1;
/// Both EL0 counter-read enables, the state a task without `PR_TSC_SIGSEGV`
/// runs under.
pub const CNTKCTL_EL0_COUNTER_ACCESS: u64 = CNTKCTL_EL0PCTEN | CNTKCTL_EL0VCTEN;

/// The CNTKCTL_EL1 value `set_el0_counter_access` would install over `cur`.
/// Pure, so the bit math is reachable from `cargo test` on any host — the
/// sysreg RMW below is not.
/// # C: O(1)
pub fn cntkctl_with_counter_access(cur: u64, allow: bool) -> u64 {
    if allow { cur | CNTKCTL_EL0_COUNTER_ACCESS } else { cur & !CNTKCTL_EL0_COUNTER_ACCESS }
}

/// Force EL0 counter-read access to `allow` on the PE this call runs on.
///
/// Denying it makes an EL0 `mrs CNTVCT_EL0` trap to EL1 as a sysreg access
/// (ESR EC 0x18) instead of returning the counter; the trap handler then
/// decides between emulating the read and raising SIGSEGV. This is the
/// aarch64 half of `prctl(PR_SET_TSC)`, so it is re-asserted on every context
/// switch whose incoming task disagrees with the outgoing one.
///
/// # SAFETY: privileged sysreg RMW on this PE's CNTKCTL_EL1; callers run
/// preempt-off so no nested switch interleaves the read-modify-write, and no
/// other CNTKCTL field is disturbed. The `isb` retires the change before EL0
/// resumes.
/// # C: O(1)
/// # Ctx: process|irq; preempt-off
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn set_el0_counter_access(allow: bool) {
    // SAFETY: per fn contract — CNTKCTL_EL1 is this PE's EL1 timer-control register; RMW touches only the two EL0 counter-read enables.
    unsafe {
        let cur: u64;
        core::arch::asm!("mrs {v}, cntkctl_el1", v = out(reg) cur, options(nomem, nostack, preserves_flags));
        let want = cntkctl_with_counter_access(cur, allow);
        if want != cur {
            core::arch::asm!(
                "msr cntkctl_el1, {v}",
                "isb",
                v = in(reg) want,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
}

/// Host build: no CNTKCTL_EL1 to program.
/// # SAFETY: no-op; exists so callers need no target gate of their own.
/// # C: O(1)
#[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
pub unsafe fn set_el0_counter_access(allow: bool) { let _ = allow; }

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
