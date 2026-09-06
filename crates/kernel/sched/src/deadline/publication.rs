use core::sync::atomic::{AtomicU64, Ordering};
use sync::IrqGate;

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
type Irq = hal_x86_64::X86IrqGate;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
type Irq = hal_aarch64::ArmIrqGate;
#[cfg(all(not(target_os = "oxide-kernel"), not(test)))]
type Irq = sync::NoopIrq;
#[cfg(test)]
type Irq = tests::TestIrq;

// Entity-owner locks serialize writers. Mask IRQ/preempt readers before odd
// publication; restore their entry state only after the generation is even.
pub(super) struct Publication<'a> { seq: &'a AtomicU64, flags: u64 }

impl<'a> Publication<'a> {
    pub(super) fn begin(seq: &'a AtomicU64) -> Self {
        // SAFETY: Publication retains these local IRQ flags until its matching drop.
        let flags = unsafe { Irq::save_disable() };
        crate::preempt::preempt_disable();
        let previous = seq.fetch_add(1, Ordering::AcqRel);
        hal::kassert!(previous & 1 == 0, "concurrent deadline entity writers");
        Self { seq, flags }
    }
}

impl Drop for Publication<'_> {
    fn drop(&mut self) {
        let previous = self.seq.fetch_add(1, Ordering::Release);
        hal::kassert!(previous & 1 != 0, "deadline entity write ended without owner");
        crate::preempt::preempt_enable_no_check();
        // SAFETY: flags were saved by this Publication on the same CPU at begin.
        unsafe { Irq::restore(self.flags); }
    }
}

#[cfg(test)]
#[path = "tests/publication_irq.rs"]
mod tests;
