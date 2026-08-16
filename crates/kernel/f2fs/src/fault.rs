//! Injected failures: which sites can fail, how often, and who is counting.
//!
//! A log-structured filesystem's error paths are the half that never runs on a
//! healthy medium — the orphan list, the recovery scan, the out-of-segment
//! allocator — so the only way to exercise them is to make an allocation or a
//! read fail on purpose, at a named site, at a chosen rate. That is what this
//! is for, and it is why the site list is an ABI: a test names sites by bit.
//!
//! Module manifest:
//! - `types`: the sites, their bit positions, and their names.
//! - `attr`:  the live counter, what changes it, and the per-site decision.

pub mod types;
pub mod attr;

pub use types::{Fault, Timeout, ALL_TYPES, FAULT_MAX, TIMEOUT_MAX};
pub use attr::{apply, build, time_to_inject, Cfg, Info, Which};

#[cfg(test)]
#[path = "tests/fault.rs"]
mod tests;

/// Every site driven through the operation that consults it.
#[cfg(test)]
#[path = "tests/faultsites.rs"]
mod site_tests;
