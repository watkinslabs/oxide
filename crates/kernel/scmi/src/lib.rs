//! System Control and Management Interface protocol clients.
//!
//! Transports own physical channels and completion; this crate owns only
//! target-independent SCMI protocol messages.
//!
//! Module manifest: `error` — failures; `transport` — channel contract;
//! `perf` — SCMI Performance protocol v1–v4.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod error;
mod perf;
mod transport;

pub use error::{Error, Result};
pub use perf::{Domain, OperatingPoint, Performance};
pub use transport::Transport;

#[cfg(test)]
mod tests;
