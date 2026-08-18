//! Regulator-provider registry.
//!
//! Module manifest:
//! - `registry` — voltage-operation registration and dispatch.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod registry;

pub use registry::{AvailabilityListener, Regulator, RegulatorOps, Voltage, by_phandle, register,
                   subscribe_availability};
