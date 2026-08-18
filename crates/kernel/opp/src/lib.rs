//! Operating-point transition ownership.
//!
//! Module manifest:
//! - `domain` — ordered voltage/clock transitions over one OPP table.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod domain;

pub use domain::{Domain, OperatingPoint};
