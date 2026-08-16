//! Segment cleaning: getting back the space out-of-place writing strands.
//!
//! Module manifest:
//! - `victim`:  which SECTION is worth cleaning, over the table alone, under
//!              a bounded search that resumes where the last one stopped.
//! - `live`:    whether a block of the victim is still in use, by all three
//!              records that describe it.
//! - `migrate`: moving one live block and repointing its owner.
//! - `collect`: cleaning a section, cleaning until there is room, and taking
//!              the checkpoint that turns what was cleaned into space.

pub mod victim;
pub mod live;
pub mod migrate;
pub mod collect;

pub use collect::{balance_choice, Balance};
pub use live::alive;
pub use migrate::Owner;
pub use victim::{Found, Policy, Search, SegInfo, Unit};

#[cfg(test)]
#[path = "../tests/gc.rs"]
mod tests;
