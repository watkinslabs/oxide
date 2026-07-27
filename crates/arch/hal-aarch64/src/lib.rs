// aarch64 HAL impls per docs/21.
//
// Scope landed: IrqGate (DAIF save + `msr daifset, #2` mask IRQ) per
// `06§3.1`. Halt (`wfi`) + mmio_barrier (`dsb sy`) per `21§4`. Larger
// CpuOps surface (per-CPU base via TPIDR_EL1, current_cpu) lands once
// the per-CPU primitive does.
//
// Asm is gated `#[cfg(all(target_arch="aarch64", target_os="oxide-kernel"))]`
// so the file compiles cleanly on:
//   - kernel target: real asm.
//   - host (`cargo test --workspace`): no-op fallback.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};

use hal::{CpuOps, Nanos, TimerOps};
use sync::IrqGate;

mod context;
mod cpuid;
mod fault;
mod exception_table;
mod fpu;
mod mmu;
pub mod mmu_ops;
pub mod pci;
pub mod pl011;
pub mod psci;
pub mod smp;
mod pt_regs;
// aarch64-kernel only: pure EL1 system-register asm, and hal-aarch64 is also
// built for the host (see vbar.rs's install_default_compiles_on_host test).
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
mod badstack;
mod regs;
// Oops register dump — compiled only where the fault path prints (`fault.rs`).
#[cfg(any(feature = "debug-irq", feature = "debug-watchdog"))]
mod showregs;
pub mod timer;
mod signal;
mod vbar;
mod uaccess;
pub mod vmm;
pub use cpuid::midr_el1;
pub use regs::{
    read_mair_el1, read_sctlr_el1, read_tcr_el1, read_ttbr0_el1, read_ttbr1_el1,
};
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub use badstack::{install_probe as install_badstack_probe, BadStackProbe};
pub use vbar::{arm_overflow_stack, install_default as install_default_vbar, current_svc_frame, on_irq_stack, set_current_kstack_top, set_current_svc_frame, set_irq_stack_top, SvcFrame, VECTOR_ENTRY_BYTES, VECTOR_TABLE_SIZE};
pub use signal::{build_signal_frame, restart_ignored_syscall, restore_signal_frame, rt_sigreturn_frame_range, svc_frame_user_sp};
pub use fault::{install_ctx_dump, install_fault_handler, CtxDumpFn, FaultHandler};
pub use fpu::{fpu_disable, fpu_enable, fpu_restore, fpu_save, FpuStateAArch64, FPU_OWNER, FPU_STATE_BYTES};
pub use context::{ContextAArch64, ForkRegs};
pub use mmu::{
    flush_local_all, flush_local_va, va_to_indices, PteArm64, PteFlags, PtIndices,
    ENTRIES_PER_TABLE, L0_SHIFT, L1_SHIFT, L2_SHIFT, L3_SHIFT, PTE_PHYS_MASK,
};
pub use pt_regs::PtRegsAArch64;
pub use uaccess::{raw_copy_from_user, raw_copy_to_user};

/// IRQ gate: save DAIF, set the I (IRQ) bit. Restore DAIF on release.
/// Per `06§3.1` we mask IRQ only — FIQ is not used in our model.
pub struct ArmIrqGate;

impl IrqGate for ArmIrqGate {
    /// # SAFETY: hardware-state mutation on this CPU; returned word is
    /// the prior DAIF and must be passed to a single `restore` call.
    /// # C: O(1)
    unsafe fn save_disable() -> u64 {
        #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
        {
            let flags: u64;
            // SAFETY: `mrs daif` reads the privilege-level interrupt
            // mask register; `msr daifset, #2` sets the I bit, masking
            // IRQs at EL1. ARM ARM B1.4 / D8.2.84 (DAIF).
            unsafe {
                core::arch::asm!(
                    "mrs {f}, daif",
                    "msr daifset, #2",
                    f = out(reg) flags,
                    options(nomem, preserves_flags),
                );
            }
            flags
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
        { 0 }
    }

    /// # SAFETY: hardware-state mutation on this CPU; returned word is the
    /// prior DAIF and must be passed to a single `restore`. Clears the I bit
    /// (`msr daifclr, #2`) so a bounded IF-off section (a syscall/fault
    /// waiting on slow block I/O) runs with IRQs live, per `06§3.1`.
    /// # C: O(1)
    unsafe fn save_enable() -> u64 {
        #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
        {
            let flags: u64;
            // SAFETY: `mrs daif` snapshots the mask bits before we unmask;
            // `msr daifclr, #2` clears the I bit, enabling IRQs at EL1.
            unsafe {
                core::arch::asm!(
                    "mrs {f}, daif",
                    "msr daifclr, #2",
                    f = out(reg) flags,
                    options(nomem, preserves_flags),
                );
            }
            flags
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
        { 0 }
    }

    /// # SAFETY: restores DAIF from caller-provided word produced by a
    /// matching `save_disable`.
    /// # C: O(1)
    unsafe fn restore(flags: u64) {
        #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
        {
            // SAFETY: `msr daif, x` sets the four interrupt-mask bits
            // from the caller-provided saved value; only DAIF bits in
            // the high byte are observable.
            unsafe {
                core::arch::asm!(
                    "msr daif, {f}",
                    f = in(reg) flags,
                    options(nomem),
                );
            }
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
        { let _ = flags; }
    }
}

/// Halt this CPU until next IRQ. `wfi` per `21§4`.
/// # C: O(1)
/// # Ctx: idle path
pub fn halt() {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `wfi` parks the core until any wake event; it is
        // unprivileged on EL1 and has no memory effects.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)) };
    }
}

/// Memory barrier ordering MMIO writes per `06§2`.
/// # C: O(1)
pub fn mmio_barrier() {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `dsb sy` orders all earlier loads + stores before any
        // subsequent ones, system-wide. ARM ARM B2.3.10.
        unsafe { core::arch::asm!("dsb sy", options(nomem, nostack, preserves_flags)) };
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// CpuOps (`21§7`)
// ---------------------------------------------------------------------------

/// `current_cpu` reads the first word at `[TPIDR_EL1]` — the per-CPU
/// area's first slot is `cpu_id`. Boot writes `TPIDR_EL1` via
/// `set_percpu_base` after carving the area out of BSS. Until SMP
/// support lands, `cpu_count` is 1 and the boot CPU stamps cpu_id=0.
pub struct ArmCpuOps;

impl CpuOps for ArmCpuOps {
    /// `AT_HWCAP` for aarch64. Advertises the ARMv8-A *mandatory* baseline
    /// — `HWCAP_FP` (1<<0) + `HWCAP_ASIMD` (1<<1) — which every ARMv8-A
    /// core (and the QEMU `virt` default CPU) is guaranteed to implement,
    /// so userspace NEON paths are always safe. Optional crypto-extension
    /// bits (AES/PMULL/SHA) are intentionally NOT set without reading
    /// `ID_AA64ISAR0_EL1`, to avoid ever advertising an absent instruction.
    /// # C: O(1)
    fn cpu_hwcap() -> u64 {
        const HWCAP_FP: u64 = 1 << 0;
        const HWCAP_ASIMD: u64 = 1 << 1;
        // Baseline (mandatory on ARMv8-A) | optional crypto/CRC bits decoded
        // from ID_AA64ISAR0_EL1 (set only for features the CPU actually has).
        HWCAP_FP | HWCAP_ASIMD | crate::cpuid::isar0_hwcap(crate::cpuid::id_aa64isar0_el1())
    }

    /// # C: O(1)
    fn current_cpu() -> u32 {
        #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
        {
            let id: u32;
            // SAFETY: boot sets TPIDR_EL1 to a per-CPU area whose
            // first u32 is cpu_id (see set_percpu_base contract).
            // `mrs` reads the system register; `ldr` follows it.
            unsafe {
                let base: usize;
                core::arch::asm!(
                    "mrs {b}, tpidr_el1",
                    b = out(reg) base,
                    options(nomem, nostack, preserves_flags),
                );
                core::arch::asm!(
                    "ldr {id:w}, [{b}]",
                    b  = in(reg) base,
                    id = out(reg) id,
                    options(readonly, nostack, preserves_flags),
                );
            }
            id
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
        { 0 }
    }

    /// v1 single-CPU; SMP enumeration lands with the GICv3 bring-up.
    /// # C: O(1)
    fn cpu_count() -> u32 { 1 }

    /// # C: O(1)
    fn halt() { halt(); }

    /// # C: O(1)
    fn mmio_barrier() { mmio_barrier(); }

    /// # SAFETY: caller asserts `base` points to a valid per-CPU
    /// area whose first word is the cpu_id.
    /// # C: O(1)
    unsafe fn set_percpu_base(base: *mut u8) {
        #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
        {
            // SAFETY: `msr tpidr_el1, x` writes the EL1 thread-id
            // system register; that's the kernel-side per-CPU base
            // per `21§7`. EL1-only insn.
            unsafe {
                core::arch::asm!(
                    "msr tpidr_el1, {b}",
                    b = in(reg) base,
                    options(nomem, nostack, preserves_flags),
                );
            }
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
        { let _ = base; }
    }
}

// ---------------------------------------------------------------------------
// TimerOps (`21§12`)
// ---------------------------------------------------------------------------

/// Generic-timer counter frequency in kHz, set at boot by reading
/// `CNTFRQ_EL0` (which the firmware programs). Zero until calibrated;
/// `monotonic_ns` returns 0 in that window so callers don't divide by
/// zero.
static CNTFRQ_KHZ: AtomicU32 = AtomicU32::new(0);

/// Boot-time hook: stash the generic-timer frequency in kHz. Spec
/// `23§3` reads `CNTFRQ_EL0` and divides by 1000 here.
/// # C: O(1)
pub fn set_cntfrq_khz(freq: u32) {
    CNTFRQ_KHZ.store(freq, Ordering::Relaxed);
}

/// Read CNTVCT_EL0 — virtual count register, monotonic since reset.
fn read_cntvct() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: `mrs CNTVCT_EL0` reads the unprivileged virtual
        // generic-timer counter; available at any EL with no memory
        // effects. ARM ARM D11.2.4.
        unsafe {
            core::arch::asm!(
                "mrs {v}, cntvct_el0",
                v = out(reg) v,
                options(nomem, nostack, preserves_flags),
            );
        }
        v
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    {
        // Host fallback: monotonic counter.
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        n as u64
    }
}

pub struct ArmTimerOps;

impl TimerOps for ArmTimerOps {
    /// # C: O(1)
    fn monotonic_ns() -> Nanos {
        let khz = CNTFRQ_KHZ.load(Ordering::Relaxed);
        if khz == 0 { return Nanos(0); }
        Nanos(hal::time::counter_ns(read_cntvct(), khz))
    }

    /// # SAFETY: writes `CNTV_CVAL_EL0` (compare value); caller owns
    /// `CNTV_CTL_EL0.ENABLE` per `23§4`.
    /// # C: O(1)
    unsafe fn set_oneshot(deadline_ns: Nanos) {
        let khz = CNTFRQ_KHZ.load(Ordering::Relaxed);
        if khz == 0 { return; }
        #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
        {
        let cycles = ((deadline_ns.0 as u128).saturating_mul(khz as u128)
            / 1_000_000).min(u64::MAX as u128) as u64;
        let target = cycles.max(read_cntvct().saturating_add(1));
        crate::timer::set_period(0);
        // SAFETY: this PE owns CNTV_CVAL/CTL and its virtual timer PPI is enabled.
        unsafe {
            core::arch::asm!("msr cntv_cval_el0, {v:x}", v = in(reg) target,
                options(nomem, nostack, preserves_flags));
            let enabled: u64 = 1;
            core::arch::asm!("msr cntv_ctl_el0, {v:x}", v = in(reg) enabled,
                options(nomem, nostack, preserves_flags));
        }
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
        let _ = deadline_ns;
    }

    /// # C: O(1)
    fn freq_khz() -> u32 { CNTFRQ_KHZ.load(Ordering::Relaxed) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sync::{Buddy, Spinlock};

    #[test]
    fn irqgate_noop_on_host() {
        // SAFETY: hosted test; arch-asm cfg'd out on this target.
        let f = unsafe { ArmIrqGate::save_disable() };
        assert_eq!(f, 0);
        // SAFETY: hosted test; restore path is no-op on this target.
        unsafe { ArmIrqGate::restore(f) };
    }

    #[test]
    fn lock_irqsave_works_with_arm_gate() {
        let s: Spinlock<u32, Buddy> = Spinlock::new(0);
        let mut g = s.lock_irqsave::<ArmIrqGate>();
        *g = 11;
        drop(g);
        assert_eq!(*s.lock(), 11);
    }

    #[test]
    fn mmio_barrier_compiles_and_runs() {
        mmio_barrier();
    }

    #[test]
    fn halt_compiles_on_host_no_panic() {
        halt();
    }

    #[test]
    fn arm_cpuops_host_fallback_returns_cpu_zero() {
        assert_eq!(ArmCpuOps::current_cpu(), 0);
        assert_eq!(ArmCpuOps::cpu_count(),    1);
    }

    #[test]
    fn arm_cpuops_set_percpu_base_compiles_on_host() {
        let mut buf = [0u8; 64];
        // SAFETY: host-only; the asm path is cfg'd out, so this just
        // exercises the no-op fallback. The buffer outlives the call.
        unsafe { ArmCpuOps::set_percpu_base(buf.as_mut_ptr()) };
    }

    #[test]
    fn arm_timer_returns_zero_until_calibrated() {
        let pre = ArmTimerOps::freq_khz();
        if pre == 0 {
            assert_eq!(ArmTimerOps::monotonic_ns(), Nanos(0));
        }
    }

    #[test]
    fn arm_timer_after_set_cntfrq_khz_is_nonzero() {
        set_cntfrq_khz(50_000); // 50 MHz typical CNTFRQ
        assert_eq!(ArmTimerOps::freq_khz(), 50_000);
        let a = ArmTimerOps::monotonic_ns();
        let b = ArmTimerOps::monotonic_ns();
        assert!(b.0 >= a.0, "monotonic_ns must be non-decreasing");
        set_cntfrq_khz(0);
    }
}
