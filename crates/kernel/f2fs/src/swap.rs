//! Swap areas: a file whose blocks the paging code addresses directly.
//!
//! Swap is the one caller that is handed a filesystem's block addresses and
//! then reads and writes them without asking again. Everything else about a
//! log-structured volume — out-of-place writes, the cleaner moving live blocks
//! to compact a section — is a promise that addresses do NOT stay put, so a
//! swap area is only possible on a file that has been taken out of all of it.
//! That is why activation PINS the file: not as a hint, but because the
//! alternative is the paging code reading a block that now belongs to
//! something else.
//!
//! Two more conditions follow from the same place. The file may not have
//! holes, because a hole has no address to hand over. And its runs are
//! wanted section-aligned, because a section is what the cleaner chooses and
//! a run that shares a section with anything else keeps that section from ever
//! being reclaimed; a file that is not already aligned is moved into pinned
//! sections rather than refused, since nothing has been told its addresses
//! yet.
//!
//! Module manifest:
//! - `policy`:  what refuses an activation, as pure decisions.
//! - `extents`: the runs handed over, and whether one is aligned.
//! - `ops`:     activation and deactivation against a mounted volume.

pub mod policy;
pub mod extents;
pub mod ops;

pub use extents::{Extent, SwapMap};
pub use policy::SwapFacts;

#[cfg(test)]
#[path = "tests/swap.rs"]
mod tests;
