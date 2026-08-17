//! Moving a range of blocks from one file into another without copying them.
//!
//! The blocks do not move. Their ADDRESSES move: the source's slots are
//! cleared and the destination's slots are made to hold what the source's
//! held, so a gigabyte changes owner for the cost of rewriting a handful of
//! node blocks. That is the whole reason this exists — a copy would read and
//! write the gigabyte, and on flash it would also wear it.
//!
//! Two things make repointing dangerous, and both decide the shape here:
//!
//! - **A block's owner is recorded twice.** The file's node holds the address,
//!   and the segment's SUMMARY block holds the owning node and slot — that is
//!   what lets the cleaner move a block and repoint whoever has it. Repointing
//!   the node without the summary leaves the cleaner believing the source
//!   still owns the block; the next clean puts the block back into the source
//!   and leaves the destination pointing at whatever took its place.
//! - **A summary already on the medium belongs to the last checkpoint.**
//!   Rewriting one in place breaks the one rule the format is built on. So a
//!   block is repointed only while its summary is still in an OPEN LOG, where
//!   nothing on the medium describes its ownership yet; every other block is
//!   copied to a fresh block and the source's slot punched. Both produce the
//!   same file contents, the same sizes and the same block counts — the
//!   difference is invisible above this layer, and the choice is what keeps a
//!   crash recoverable.
//!
//! Alignment is not a convenience. A block is the unit an address names, so a
//! move whose ends are not on block boundaries cannot be expressed as a change
//! of addresses at all; the one exception is a source range ending exactly at
//! the end of the file, whose last partial block is taken whole.
//!
//! Module manifest:
//! - `plan`:     the refusal ladder and the range arithmetic, over stated facts.
//! - `exchange`: repointing and copying the blocks themselves.
//! - `run`:      the two inodes, start to finish.

pub mod plan;
pub mod exchange;
pub mod run;

pub use plan::{plan, Facts, Plan};
