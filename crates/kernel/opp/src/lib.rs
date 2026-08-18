//! Operating-point transition ownership.
//!
//! Module manifest:
//! - `binding` — hardware-version filtering and PM-domain state ownership.
//! - `domain` — ordered voltage/clock transitions over one OPP table.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod binding;
mod domain;

pub use binding::{AvailabilityListener, PerformanceOps, register_performance_domain,
                  register_supported_hardware, set_performance_state, subscribe_availability,
                  supports_hardware};
pub use domain::{Domain, OperatingPoint, RequiredState};
