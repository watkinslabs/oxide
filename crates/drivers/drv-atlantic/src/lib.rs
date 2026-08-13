//! Atlantic AQC113 controller contracts.
//!
//! Module manifest:
//! - `atl2_reset`: firmware-managed controller reset transaction.
//! - `atl2_mailbox`: firmware shared-buffer ownership transaction.
//! - `atl2_regs`: descriptor and queue-register ABI.
//! - `atl2_queue`: validated queue geometry and register values.
//! - `atl2_dma`: target-only IOMMU-backed queue-memory ownership.
//! - `atl2_program`: queue-register publication order.
//! - `atl2_filter`: firmware-owned action-resolver initialization.
//! - `atl2_controller`: target-only firmware and queue lifecycle owner.
//! - `imp`: target-only PCI, IRQ, and net-device lifecycle owner.

#![no_std]

extern crate alloc;

pub mod atl2_reset;
pub mod atl2_mailbox;
pub mod atl2_regs;
pub mod atl2_queue;
pub mod atl2_program;
pub mod atl2_filter;
#[cfg(target_os = "oxide-kernel")]
pub mod atl2_dma;
#[cfg(target_os = "oxide-kernel")]
pub mod atl2_controller;
#[cfg(target_os = "oxide-kernel")]
mod imp;
#[cfg(target_os = "oxide-kernel")]
pub use imp::ATLANTIC_DRIVER;
