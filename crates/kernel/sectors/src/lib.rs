#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

//! Where an on-disk filesystem's sectors come from.
//!
//! Every filesystem that reads a fixed-size unit off a partition — FAT, exFAT,
//! NTFS — needs the same two things: a trait it can be tested against without
//! a disk, and one adapter that turns a volume-sector request into a
//! block-device request when the two units differ. Keeping a copy per
//! filesystem would put the read-modify-write rule in three places, and a
//! partial-block write that forgets it destroys the bytes either side.
//!
//! Module manifest:
//! - `source`: the trait a volume reads through, and the in-memory image that
//!             implements it for tests.
//! - `device`: the adapter over a registered block device.

extern crate alloc;

pub mod source;
pub mod device;

pub use source::{MemImage, SectorSource};
pub use device::BlockSource;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
