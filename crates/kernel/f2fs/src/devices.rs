//! A volume's member devices, and which one a block address lives on.
//!
//! A volume may be spread over as many as eight devices. The superblock names
//! them — a path and a segment count each — and the segment counts alone fix
//! the arithmetic: the members tile ONE address space in the order they are
//! listed, so a block address is global and the device it lands on is found by
//! walking the spans. Nothing on the medium records a per-device address.
//!
//! Two things make this worth its own module rather than a branch at each
//! read. First, the first member's span is not `segments * blocks_per_segment`
//! — it also covers the metadata that precedes segment zero, so an
//! implementation that tiles from the main area alone puts every block on the
//! wrong device by a constant offset. Second, once the mapping exists, discard
//! and flush must use it too: a discard aimed at the wrong member erases live
//! data on it, which is the worst outcome this filesystem can produce.
//!
//! Module manifest:
//! - `table`: the member spans, and the address-to-member lookup.
//! - `route`: one medium over the members, split at their boundaries.
//! - `barrier`: when a device is asked to empty its write cache, which member
//!              owes one, and what a failed one costs.
//! - `flush`: the segment range one member's blocks occupy.
//! - `alias`: a file that stands for a whole member device.

pub mod table;
pub mod route;
pub mod barrier;
pub mod flush;
pub mod alias;

pub use table::{DevInfo, DevSpec, DevTable};
pub use route::DeviceSet;

#[cfg(test)]
#[path = "tests/devices/mod.rs"]
mod tests;
