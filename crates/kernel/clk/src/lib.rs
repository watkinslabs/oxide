//! Clock-provider registry.
//!
//! Module manifest:
//! - `registry` — provider registration and rate-operation dispatch.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod registry;

pub use registry::{AvailabilityListener, Clock, ClockOps, ClockSpec, by_spec, register,
                   subscribe_availability};
