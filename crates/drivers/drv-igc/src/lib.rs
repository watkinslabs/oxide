//! Intel I225/I226 Ethernet controller contract.
//!
//! Module manifest:
//! - `regs`: PCI identity, MMIO queue geometry, and descriptor layouts.
//! - `queue`: validated queue geometry and MMIO programming values.

#![no_std]

pub mod regs;
pub mod queue;
