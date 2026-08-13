#![no_std]

//! Native RTL8125 2.5GbE hardware definitions and driver implementation.

pub mod regs;
pub mod bringup;
pub mod dma;
pub mod rtl_firmware;
#[cfg(target_os = "oxide-kernel")]
mod dma_owner;
#[cfg(target_os = "oxide-kernel")]
mod imp;
#[cfg(target_os = "oxide-kernel")]
pub use imp::RTL8125_DRIVER;
