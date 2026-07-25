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

    /// # SAFETY: hardware-state mutation on this CPU; the returned flags
    /// must be paired with a single `restore` call. Enables IRQs (`sti`)
    /// so a bounded IF=0 section (a syscall/fault waiting on slow block
    /// I/O) can run with the timer tick + wakeups live, per `06§3.1`.
    /// # C: O(1)
    unsafe fn save_enable() -> u64 {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        {
            let flags: u64;
            // SAFETY: pushfq snapshots RFLAGS (IF@bit9) before we set IF;
            // sti enables maskable IRQs at CPL=0. Restore via popfq (restore).
            unsafe {
                core::arch::asm!(
                    "pushfq",
                    "pop {f}",
                    "sti",
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
