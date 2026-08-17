//! Rewriting a range of a file so its blocks land next to each other.
//!
//! Out-of-place update scatters a file: every byte changed takes a fresh block
//! from the tail of a log, so a file written a little at a time ends up with
//! its logical order and its physical order unrelated. Nothing is WRONG with
//! such a file — every read returns the right bytes — but each read costs a
//! seek the layout could have avoided, and the cached extent, which describes
//! exactly one contiguous run, stops covering anything.
//!
//! Two passes, and the first one is the point. The survey decides whether the
//! range is fragmented AT ALL, because rewriting a contiguous range moves
//! every block for no gain and burns a section of log doing it. Only a range
//! whose blocks are already discontiguous is rewritten, and only when there
//! are enough free sections to hold the copy — a rewrite that runs out of log
//! part way through leaves the file MORE fragmented than it started.
//!
//! Holes are not fragmentation. A file whose blocks are `[100, hole, 101]` is
//! perfectly laid out: the two blocks that exist are adjacent, and the gap
//! costs nothing because nothing is read from it. A survey that reset its
//! run at every hole would report a sparse file as fragmented and rewrite it
//! on every call, forever.
//!
//! Module manifest:
//! - `plan`: whether a range is fragmented, and what a rewrite would cost.
//! - `run`:  carrying the two passes out against a mounted volume.

pub mod plan;
pub mod run;

pub use plan::{Facts, Survey};
