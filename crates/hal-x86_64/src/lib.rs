// x86_64 HAL impls per docs/20.
//
// Scope landed: IrqGate (RFLAGS save + `cli` / RFLAGS restore) per
// `06§3.1`. Halt + mmio_barrier per `20§4`. Larger CpuOps surface
// (per-CPU base, current_cpu) lands once the per-CPU primitive does.
//
// Asm is gated `#[cfg(all(target_arch="x86_64", target_os="oxide-kernel"))]`
// so the same source file compiles cleanly on:
//   - kernel target (`*-unknown-oxide-kernel`): real asm.
//   - host (`cargo test --workspace`): no-op fallback.
// This keeps the workspace one-build-graph without sidestepping the
// "no static mut" / "no dyn HAL" / "no extern crate std" rules.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use sync::IrqGate;

/// IRQ gate: save RFLAGS + clear IF (`cli`) on disable; restore RFLAGS
/// (which restores IF) on restore. Pairs with `Spinlock::lock_irqsave`
/// per `06§3.1`.
pub struct X86IrqGate;

impl IrqGate for X86IrqGate {
    /// # SAFETY: hardware-state mutation on this CPU; the returned
    /// flags must be paired with a single `restore` call before any
    /// other code path expects IRQs in their pre-disable state.
    /// # C: O(1)
    unsafe fn save_disable() -> u64 {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        {
            let flags: u64;
            // SAFETY: pushfq + cli is the canonical save+disable
            // sequence on x86_64 per Intel SDM Vol. 2 + AMD APM.
            unsafe {
                core::arch::asm!(
                    "pushfq",
                    "pop {f}",
                    "cli",
                    f = out(reg) flags,
                    options(nomem, preserves_flags),
                );
            }
            flags
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
        { 0 }
    }

    /// # SAFETY: restores RFLAGS from caller-provided word that came
    /// from the matching `save_disable` invocation.
    /// # C: O(1)
    unsafe fn restore(flags: u64) {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        {
            // SAFETY: popfq writes IF + other RFLAGS bits from the
            // saved word; legal on any privilege level for kernel.
            unsafe {
                core::arch::asm!(
                    "push {f}",
                    "popfq",
                    f = in(reg) flags,
                    options(nomem),
                );
            }
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
        { let _ = flags; }
    }
}

/// Halt this CPU until the next IRQ. `hlt` per `20§4`. On host fallback,
/// returns immediately so hosted unit tests can exercise call sites.
/// # C: O(1)
/// # Ctx: idle path
pub fn halt() {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `hlt` is a privileged instruction; in kernel mode
        // (CPL=0) it parks the core until the next IRQ — no memory
        // effects beyond architectural state.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)) };
    }
}

/// Memory barrier ordering MMIO writes per `06§2`.
/// # C: O(1)
pub fn mmio_barrier() {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `mfence` is unprivileged; orders all loads + stores
        // before any subsequent loads + stores per Intel SDM 8.2.5.
        unsafe { core::arch::asm!("mfence", options(nomem, nostack, preserves_flags)) };
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
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
        // Host build: save_disable returns 0; restore is a no-op.
        // SAFETY: hosted test entry; arch-asm path is cfg'd out so this
        // exercises only the no-op fallback per the cfg gates above.
        let f = unsafe { X86IrqGate::save_disable() };
        assert_eq!(f, 0);
        // SAFETY: hosted test; restore path is no-op on this target.
        unsafe { X86IrqGate::restore(f) };
    }

    #[test]
    fn lock_irqsave_works_with_x86_gate() {
        let s: Spinlock<u32, Buddy> = Spinlock::new(0);
        let mut g = s.lock_irqsave::<X86IrqGate>();
        *g = 7;
        drop(g);
        assert_eq!(*s.lock(), 7);
    }

    #[test]
    fn mmio_barrier_compiles_and_runs() {
        mmio_barrier();
    }

    #[test]
    fn halt_compiles_on_host_no_panic() {
        // Host build: halt is a no-op, returns immediately.
        halt();
    }
}
