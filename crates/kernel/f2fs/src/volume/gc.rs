//! Segment cleaning: getting back the space out-of-place writing strands.
//!
//! Module manifest:
//! - `victim`:  which segment is worth cleaning, over the table alone.
//! - `live`:    whether a block of the victim is still in use, by all three
//!              records that describe it.
//! - `migrate`: moving one live block and repointing its owner.
//! - `collect`: cleaning a segment, and cleaning until there is room.

pub mod victim;
pub mod live;
pub mod migrate;
pub mod collect;

pub use live::alive;
pub use migrate::Owner;
pub use victim::{Policy, SegInfo};

#[cfg(test)]
#[path = "../tests/gc.rs"]
mod tests;
