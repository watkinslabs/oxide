#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

// Module manifest:
// - `uapi`: link-message attribute numbers and header geometry.
// - `nla`: attribute walking and building.
// - `msg`: the link message and its `IFLA_LINKINFO` envelope.
// - `registry`: the link-kind table and the create/change/delete dispatch.

pub mod uapi;
pub mod nla;
pub mod msg;
pub mod registry;

pub use msg::{IfInfo, LinkMsg, parse, put_linkinfo};
pub use registry::{LinkKindOps, RegisterError, dellink, kind_of, kinds, lookup, newlink,
                   register, unregister};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
