//! Where a write lands: back on the block it came from, or on a fresh one.
//!
//! Two decisions, one question. A page being written back either overwrites the
//! block that held it — cheap, and only legal in states the format's recovery
//! model survives — or takes a new one; and a log that has filled its segment
//! either appends to an empty segment or writes into the gaps of a partly-used
//! one. Both are read per WRITE rather than per mount, and both are pure: they
//! take what the volume knows and return a choice, so they can be exercised
//! without a medium and without a kernel.
//!
//! Nothing here touches a block. The volume's own placement file gathers these
//! inputs and acts on the answers; keeping the answers separate is what lets
//! every arm of both ladders be tested, including the ones a running mount
//! reaches only in states that are hard to arrange.
//!
//! Module manifest:
//! - `bits`:   the in-place-update policies a mount can arm, and their names.
//! - `limits`: the thresholds both decisions compare against.
//! - `ipu`:    whether one page's write lands back where it was.
//! - `ssr`:    whether a log recycles a segment or opens a fresh one.
//! - `tunables`: the thresholds one mount is running with.

pub mod bits;
pub mod limits;
pub mod ipu;
pub mod ssr;
pub mod tunables;

pub use tunables::Tunables;

#[cfg(test)]
#[path = "tests/place/mod.rs"]
mod tests;
