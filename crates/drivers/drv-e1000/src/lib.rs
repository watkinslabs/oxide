// Module manifest:
// - `regs`: descriptor ABI, register offsets, and ring contracts.
// - `imp`: PCI probe, DMA ownership, transmit, and NET_RX polling.
// - `e1000e`: discrete 82571-family BM PCI driver binding.
// - `e1000e_init`: NVM and BM-PHY admission for the 82571 controller family.
// - `profile`: controller reset and DMA contracts.
// - `reset`: controller-specific reset sequencing.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]

extern crate alloc;

mod regs;
mod profile;
#[cfg(target_os = "oxide-kernel")]
mod imp;
#[cfg(target_os = "oxide-kernel")]
mod e1000e;
#[cfg(target_os = "oxide-kernel")]
mod e1000e_init;
#[cfg(target_os = "oxide-kernel")]
mod reset;

#[cfg(target_os = "oxide-kernel")]
pub use imp::E1000_DRIVER;
#[cfg(target_os = "oxide-kernel")]
pub use e1000e::E1000E_DRIVER;
