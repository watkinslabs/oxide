//! xHCI host-controller contract: capability geometry and register ownership.
//!
//! Module manifest:
//! - `regs`: xHCI capability decoding and validated register-file geometry.
//! - `ring`: command and event TRB ownership/cycle mechanics.
//! - `controller`: reset/run register sequencing and DMA register plan.
//! - `platform`: owned MMIO and coherent controller-page storage.
//! - `identity`: stable input-device identity per controller slot.

#![no_std]

pub mod regs;
pub mod ring;
#[cfg(any(test, target_os = "oxide-kernel"))]
mod completion;
pub mod controller;
pub mod context;
pub mod usb;
pub mod storage;
pub mod hid;
pub mod hid_report;
pub mod ports;
pub mod identity;
#[cfg(target_os = "oxide-kernel")]
pub mod platform;
#[cfg(target_os = "oxide-kernel")]
pub mod command;
#[cfg(target_os = "oxide-kernel")]
pub mod device;
#[cfg(target_os = "oxide-kernel")]
mod irq;
#[cfg(target_os = "oxide-kernel")]
pub(crate) mod probe;
#[cfg(target_os = "oxide-kernel")]
mod probe_input;
#[cfg(target_os = "oxide-kernel")]
mod hid_input_work;
#[cfg(target_os = "oxide-kernel")]
mod detach;
#[cfg(target_os = "oxide-kernel")]
mod probe_hub;
#[cfg(target_os = "oxide-kernel")]
mod root_hub;
#[cfg(target_os = "oxide-kernel")]
mod storage_block;
#[cfg(target_os = "oxide-kernel")]
pub use probe::XHCI_DRIVER;
