//! Reclaim-stage foundation. `state` owns queue order and PageMeta transitions;
//! `workingset` owns the shadow-entry nonresident-age clock and its recency
//! test; `tests` drives its hosted state machine.

mod state;
pub mod workingset;

pub use state::{Aging, Isolation, Lru, Reclaim, ReclaimError, ReclaimSnapshot};
pub use workingset::{nonresident_age, workingset_eviction, workingset_test_recent};

#[cfg(test)]
mod tests;
