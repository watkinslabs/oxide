//! Walking the layers, and the merged object that results.
//!
//! A name is looked up in the writable layer first and then in each lower
//! layer under the same parent, stopping at the first thing that says nothing
//! below is visible: a whiteout, an opaque directory, or a non-directory. What
//! survives is a list — one upper object and however many lower ones — and
//! every later decision reads that list rather than walking again.
//!
//! Three things make this more than a loop. A REDIRECT changes the name being
//! looked up part-way down, and an absolute one restarts the walk at each
//! layer's root, which is how a renamed directory keeps its lower half. A
//! METACOPY upper object has no data, so the walk must continue below it to
//! find some. And an ORIGIN record ties a copied-up object to the lower one it
//! came from even when no name leads there any more.
//!
//! Module manifest:
//! - `data`:   the state carried down the walk.
//! - `single`: one name in one layer, and what it says about going deeper.
//! - `walk`:   a whole layer, including a redirect's path from its root.
//! - `merge`:  every layer, into one object.

pub mod data;
pub mod single;
pub mod walk;
pub mod merge;

pub use data::Data;
pub use merge::lookup;
pub use single::check_metacopy;
pub use walk::layer;

#[cfg(test)]
#[path = "lookup/tests.rs"]
mod tests;
