//! The IRQ gate every PMM lock on the page-free path uses.
//!
//! A frame is freed from any context: a syscall dropping its last reference, a
//! fault handler unwinding, and — the case that matters — an interrupt tail,
//! since the completion softirq releases pages the driver was holding. A lock
//! on that path taken plainly lets an interrupt land on the CPU that already
//! owns it and spin for it forever, with local interrupts masked and no tick
//! to break the wait. The buddy allocator's own lock has masked interrupts for
//! this reason since it was written; the reclaim LRU, added to the same path
//! later, is reached through the identical call chain and needs the identical
//! gate.
//!
//! Hosted builds have no interrupts to mask, so the gate is the no-op one and
//! the lock behaves exactly as it did.

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub(crate) type PmmIrq = hal_x86_64::X86IrqGate;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub(crate) type PmmIrq = hal_aarch64::ArmIrqGate;
#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) type PmmIrq = sync::NoopIrq;
