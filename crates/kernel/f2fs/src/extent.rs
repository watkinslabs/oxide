//! The two extent caches a mount keeps in memory.
//!
//! A file's block address is reached by walking a tree of node blocks, and
//! every level of that walk is a block read. For the shape almost every file
//! has — one contiguous run, or a handful of them — the walk answers the same
//! question over and over, so the answers are remembered as RUNS: a file
//! offset, a length, and what the run maps to.
//!
//! Two caches, over the same shape, answering different questions:
//!
//! - The **read** cache maps a file offset to a VOLUME ADDRESS. It is what
//!   turns a sequential read of a contiguous file into one lookup instead of
//!   one node walk per block.
//! - The **block-age** cache maps a file offset to HOW LONG AGO its block was
//!   written, measured in blocks the volume has allocated since. It is what
//!   lets the allocator put data that changes together in the same place, and
//!   what the age-threshold cleaner costs its candidates by.
//!
//! Nothing here reads a medium and nothing here knows what an inode is: the
//! caller states the facts that gate caching and hands over the runs. That is
//! deliberate — a cache that can only be exercised against a real volume is a
//! cache whose invalidation rules are never tested, and a stale cache is worse
//! than no cache, because it answers CONFIDENTLY with another file's blocks.
//!
//! Module manifest:
//! - `limits`: the lengths, weights and thresholds the caches are bounded by.
//! - `info`:   one run, which cache it belongs to, and what makes two of them one.
//! - `tree`:   one inode's ordered runs, and the mount-wide order of last use.
//! - `update`: taking a change to a file's blocks into a cache.
//! - `age`:    how old a block is, and how that age is carried forward.
//! - `cache`:  both caches, and everything a caller does to them.

pub mod limits;
pub mod info;
pub mod tree;
pub mod update;
pub mod age;
pub mod cache;

pub use cache::{Caches, Temperature};
pub use info::{Gate, Hit, Info, Kind, Lookup};
pub use update::Outcome;
