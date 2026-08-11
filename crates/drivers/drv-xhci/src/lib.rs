//! xHCI host-controller contract: capability geometry and register ownership.
//!
//! Module manifest:
//! - `regs`: xHCI capability decoding and validated register-file geometry.
//! - `ring`: command and event TRB ownership/cycle mechanics.
//! - `controller`: reset/run register sequencing and DMA register plan.
//! - `platform`: owned MMIO and coherent controller-page storage.

#![no_std]

pub mod regs;
pub mod ring;
pub mod controller;
pub mod context;
pub mod ports;
#[cfg(target_os = "oxide-kernel")]
pub mod platform;
#[cfg(target_os = "oxide-kernel")]
mod irq;
#[cfg(target_os = "oxide-kernel")]
mod probe;
#[cfg(target_os = "oxide-kernel")]
pub use probe::XHCI_DRIVER;
