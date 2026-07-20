//! Reclaim-stage foundation. `state` owns queue order and PageMeta transitions;
//! `tests` drives its hosted state machine.

mod state;

pub use state::{Aging, Isolation, Lru, Reclaim, ReclaimError, ReclaimSnapshot};

#[cfg(test)]
mod tests;
