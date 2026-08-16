//! Replaying the tail a crash left after the last checkpoint.
//!
//! A checkpoint is the only thing that makes the node table on the medium
//! describe the current state, and writing one per `fsync` is far too
//! expensive. So `fsync` leaves a chain of node blocks past the checkpoint
//! instead, and this is the side that reads it: walk forward from where each
//! log stood when the checkpoint was written, keep the blocks of this
//! generation that carry the fsync mark, and put the addresses they name back
//! into the live file. Then checkpoint, so the next mount has nothing to do.
//!
//! Module manifest:
//! - `marks`:  the footer bits and offsets, as pure functions.
//! - `scan`:   walking the chain, with its version test and loop guard.
//! - `prev`:   taking a recovered block from whoever still holds it.
//! - `data`:   putting one node's worth of addresses back.
//! - `replay`: the order the whole pass runs in, and what it protects first.
//! - `policy`: what a mount does about a chain, given what it may write.

pub mod marks;
pub mod scan;
pub mod prev;
pub mod data;
pub mod replay;
pub mod policy;

pub use replay::{Recovery, Replayed};
pub use scan::Found;

/// Shared test fixture, declared here so every recovery test module reaches
/// the same one rather than each carrying a copy.
#[cfg(test)]
#[path = "../tests/recover/fixture.rs"]
pub mod fixture;

#[cfg(test)]
#[path = "../tests/recover.rs"]
mod tests;
