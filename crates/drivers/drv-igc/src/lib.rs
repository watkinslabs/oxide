//! Intel I225/I226 Ethernet controller contract.
//!
//! Module manifest:
//! - `regs`: PCI identity, MMIO queue geometry, and descriptor layouts.
//! - `queue`: validated queue geometry and MMIO programming values.
//! - `dma`: target-only IOMMU-backed descriptor and buffer ownership.
//! - `controller`: target-only reset, firmware handoff, and queue execution.
//! - `driver`: target-only PCI, IRQ, and net-device lifecycle ownership.

#![no_std]

extern crate alloc;

pub mod regs;
pub mod queue;
#[cfg(target_os = "oxide-kernel")]
pub mod dma;
#[cfg(target_os = "oxide-kernel")]
pub mod controller;
#[cfg(target_os = "oxide-kernel")]
mod driver;
#[cfg(target_os = "oxide-kernel")]
pub use driver::IGC_DRIVER;
