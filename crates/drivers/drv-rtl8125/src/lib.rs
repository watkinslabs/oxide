#![no_std]

//! Native RTL8125 2.5GbE hardware definitions and driver implementation.

pub mod regs;
pub mod bringup;
pub mod dma;
#[cfg(target_os = "oxide-kernel")]
mod dma_owner;
