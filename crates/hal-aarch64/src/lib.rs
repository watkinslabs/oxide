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

use sync::IrqGate;

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
}
