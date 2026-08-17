//! Pinned files: blocks that are promised never to move.
//!
//! A pinned file is the one file on a log-structured volume whose block
//! addresses a caller outside the filesystem may hold on to. Two things follow
//! and both are load-bearing:
//!
//! - **The cleaner may not migrate its blocks.** Out-of-place writing exists so
//!   that the cleaner can compact a segment by moving what is still live; a
//!   pinned block moved out from under a swap subsystem or a device mapper
//!   leaves that caller reading whatever now occupies the address.
//! - **A write to it is IN PLACE.** Rewriting a pinned block out of place is
//!   the same move by another name, so the block is overwritten where it lies
//!   and a write that is not an overwrite of an existing block is refused.
//!
//! Both are only safe because pinning is refused on a file that already has
//! blocks: the blocks come afterwards, out of a section reserved for them, so
//! nothing pinned is ever mixed into a section the cleaner may choose.
//!
//! Module manifest:
//! - `state`:  the pin mark and the GC-failure counter, as they are stored.
//! - `policy`: the refusal ladders, as pure decisions over stated facts.
//! - `section`: section arithmetic, apart from any volume.
//! - `alloc`:  the pinned section, and filling a pinned file out of it.
//! - `ops`:    the operations a caller invokes, against a mounted volume.

pub mod state;
pub mod policy;
pub mod section;
pub mod alloc;
pub mod ops;

pub use policy::{GcPinned, PinAction, PinFacts, SetPinGate};
pub use state::{gc_failures, is_pinned};

#[cfg(test)]
#[path = "tests/pin.rs"]
mod tests;
