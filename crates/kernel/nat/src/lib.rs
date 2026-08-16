#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

// Module manifest:
// - `uapi`: range flags, manipulation types, hook numbers and priorities.
// - `range`: the requested translation and the address/port selection inside it.
// - `unique`: the collision-avoiding tuple search.
// - `setup`: establishing a binding and replaying it per packet.
// - `manip`: rewriting the packet and its checksums.
// - `policy`: masquerade and redirect address selection.

pub mod uapi;
pub mod range;
pub mod unique;
pub mod setup;
pub mod manip;
pub mod policy;

pub use range::NatRange;
pub use setup::{SetupResult, alloc_null_binding, packet_needs_manip, setup_info,
                target_tuple};
pub use unique::{NatEnv, get_unique_tuple};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
