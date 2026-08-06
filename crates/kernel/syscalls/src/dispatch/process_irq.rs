// Syscall process-context IRQ state. Architectural entry arrives masked;
// dispatch enables IRQs after entry accounting and restores that exact state
// before return-to-user work inspects task flags.

use sync::IrqGate;

#[cfg(target_arch = "x86_64")]
type ArchIrqGate = hal_x86_64::X86IrqGate;
#[cfg(target_arch = "aarch64")]
type ArchIrqGate = hal_aarch64::ArmIrqGate;

pub(super) struct ProcessIrqs {
    flags: u64,
}

impl ProcessIrqs {
    /// Enable IRQs for ordinary syscall process context.
    /// # C: O(1)
    /// # Ctx: syscall entry, IRQs masked, no locks held
    #[inline]
    pub(super) fn enable() -> Self {
        // SAFETY: syscall entry has completed its architectural save and holds
        // no lock; Drop restores the exact entry interrupt state before exit.
        let flags = unsafe { ArchIrqGate::save_enable() };
        Self { flags }
    }
}

impl Drop for ProcessIrqs {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: `flags` is the unmatched token captured by this guard's
        // `save_enable`; the guard is dropped exactly once by the same task.
        unsafe { ArchIrqGate::restore(self.flags); }
    }
}
