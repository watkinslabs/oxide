//! Changing the allocation table: claiming free clusters, linking them into a
//! chain, releasing one, and knowing how many are left.
//!
//! Module manifest:
//! - `entry`: writing one table entry at each width, shared nibbles and all.
//! - `alloc`: the scan that claims clusters, and what a shortfall undoes.
//! - `free`:  releasing a chain, and cutting one short.
//! - `count`: establishing the free total, by scan and by maintenance.
//! - `zero`:  which newly claimed clusters must be cleared before use.

pub mod entry;
pub mod alloc;
pub mod free;
pub mod count;
pub mod zero;

pub use entry::{end_mark, write_entry, FREE_MARK};
pub use alloc::{alloc_clusters, allocate, chain_add, link_chain};
pub use free::{free_chain, free_chain_state, truncate_chain, truncate_chain_state, valid_entry};
pub use count::{count_free, count_free_clusters};
pub use zero::{zero_range, NewCluster};

#[cfg(test)]
#[path = "cluster_alloc/tests.rs"]
mod tests;
