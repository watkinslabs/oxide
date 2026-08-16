//! Moving an object into the writable layer, in an order that survives a
//! crash at any point.
//!
//! Every write to an object that exists only below has to make a copy in the
//! writable layer first. The copy is built somewhere else entirely — in the
//! work directory — and only moved into place when it is complete, so an
//! interrupted copy-up leaves the overlay exactly as it was rather than
//! leaving a truncated file where a whole one used to be.
//!
//! Two orderings inside that are contract, not preference. DATA is copied
//! before extended attributes, because writing a file's contents clears its
//! file capabilities and copying them first would silently drop them. And the
//! MOVE is last, after every attribute is in place, because the moment the
//! object appears under its name it is what every reader sees.
//!
//! Module manifest:
//! - `plan`:  what kind of copy is needed, and the order its steps run in.
//! - `attrs`: the attributes carried across, and the ones that must not be.
//! - `run`:   performing it against real layers.

pub mod plan;
pub mod attrs;
pub mod run;

pub use plan::{needs_copy_up, need_meta_copy_up, steps, Kind, Step};
pub use run::{copy_up, copy_up_data, copy_up_parents};

#[cfg(test)]
#[path = "copyup/tests.rs"]
mod tests;
