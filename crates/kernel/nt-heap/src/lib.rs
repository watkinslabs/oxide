//! NT process-heap allocator: sub-allocates blocks inside reserved regions so
//! a heap call costs no address-space work in the common path.
//!
//! Module manifest:
//! - `limits`   — block/region granularity, growth steps, class thresholds
//! - `flags`    — heap and block flag bits
//! - `layout`   — the eight-byte block header
//! - `backend`  — reserve/commit/release plus body access, supplied by the owner
//! - `heap`     — heap state: regions, free index, large blocks, user records
//! - `alloc_block` — allocation, splitting, region growth, large blocks
//! - `free`     — validation, coalescing, empty-region release
//! - `resize`   — in-place resize, else move and copy
//! - `query`    — size, validation, walk, user records

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod backend;
pub mod flags;
pub mod heap;
pub mod layout;
pub mod limits;
mod alloc_block;
mod free;
mod query;
mod resize;

pub use backend::HeapBackend;
pub use heap::Heap;
pub use query::WalkEntry;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
