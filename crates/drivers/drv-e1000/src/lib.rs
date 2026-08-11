// Module manifest:
// - `regs`: descriptor ABI, register offsets, and ring contracts.
// - `imp`: PCI probe, DMA ownership, transmit, and NET_RX polling.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]

extern crate alloc;

mod regs;
#[cfg(target_os = "oxide-kernel")]
mod imp;

#[cfg(target_os = "oxide-kernel")]
pub use imp::E1000_DRIVER;
