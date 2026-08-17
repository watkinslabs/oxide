//! Erasing a file's blocks where they lie.
//!
//! Deleting a file does not destroy its contents. It releases the blocks, and
//! the bytes stay on the medium until something else happens to be written
//! over them — which on a log-structured filesystem may be never, because the
//! allocator has a whole volume to work through first. A caller that needs the
//! bytes GONE rather than merely unreachable has to say so, and this is how.
//!
//! Nothing about the file changes. The blocks stay allocated, stay the file's,
//! and stay at the addresses its nodes record; only their CONTENTS are
//! destroyed. That is deliberate — the file afterwards is the same length with
//! the same shape, reading as whatever the medium gives back — and it is why
//! this is not a truncate and not a hole punch.
//!
//! Two ways to destroy them, either or both:
//!
//! - **Discard** hands the run to the device, which erases it in the way its
//!   own storage works — the only method that reaches bytes a controller may
//!   have remapped out from under the filesystem.
//! - **Zero out** writes zeroes over the run, which works on any medium and
//!   leaves a known value behind.
//!
//! Runs, not blocks. A device erases in large units and a request of one block
//! is nearly all overhead, so consecutive blocks that are consecutive on the
//! medium too are gathered and handed over together.
//!
//! Module manifest:
//! - `span`: which bytes the request names, and whether they are nameable.
//! - `walk`: the last index a file holds anything at, over its tree.
//! - `run`:  gathering the runs and erasing them.

pub mod span;
pub mod walk;
pub mod run;

pub use span::{span, Span};
