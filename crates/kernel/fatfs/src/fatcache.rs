//! Remembering where a file's clusters are, so a seek does not rewalk the
//! chain from its start.
//!
//! A FAT chain is a singly linked list with no index, so finding the Nth
//! cluster of a file costs N table reads. Without a cache, reading a large
//! file sequentially costs O(n²) reads for n clusters, which is the difference
//! between a usable filesystem and an unusable one on any file worth caching.
//!
//! The reference keeps a handful of positions per file, each covering a RUN of
//! contiguous clusters rather than a single one, and looks up the nearest
//! position at or before the wanted offset. That is what makes the common
//! case — a file laid out contiguously — a single cache entry covering the
//! whole thing.
//!
//! Module manifest:
//! - `lru`:  the per-file set of remembered positions, and its invalidation.
//! - `seek`: walking to the Nth cluster, consulting and extending that set.

pub mod lru;
pub mod seek;

pub use lru::{CacheId, ChainCache, FAT_MAX_CACHE};
pub use seek::{get_cluster, Seek, TO_EOF};

#[cfg(test)]
#[path = "fatcache/tests.rs"]
mod tests;
