//! Canonical block-driver and disk registry. `core.rs` owns driver-major
//! allocation and per-driver minor allocation; no consumer derives a device
//! number from a disk name.

mod core;
#[cfg(test)] mod tests;

pub use core::*;
