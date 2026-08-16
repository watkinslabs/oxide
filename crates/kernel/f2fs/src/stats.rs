//! What a mount has done, and what it looks like right now.
//!
//! Two kinds of number, kept apart on purpose. A COUNTER is a running total
//! only the mount can know — checkpoints written, blocks the cleaner moved,
//! segments opened by each allocation strategy — and it is raised at the site
//! that does the thing. Everything else is DERIVED: recomputed from the live
//! volume every time the report is read, because the volume already holds the
//! truth and a cached copy of it is a second source that can disagree.
//!
//! The rule that keeps this honest: nothing here samples a value it could
//! have counted, and nothing here counts a value it could have sampled. A
//! counter that duplicates derivable state goes wrong silently the first time
//! a site is missed; a sample of something nothing records reads zero forever
//! and says nothing happened.
//!
//! Module manifest:
//! - `counters`: what a mount accumulates, and the sites' vocabulary for it.
//! - `iostat`:   bytes and requests, split by what asked for them.
//! - `sample`:   one instant's picture, counters and live volume together.
//! - `bimodal`:  how far section occupancy is from the shape cleaning wants.
//! - `mem`:      what one mount is holding in memory.
//! - `policy`:   the in-place-update set, and the mount's condition flags.
//! - `show`:     the report's exact text, which is the part tools depend on.
//! - `registry`: every mounted volume, so one file can report them all.
//! - `inject`:   operations failed on purpose, per site.

pub mod counters;
pub mod iostat;
pub mod sample;
pub mod bimodal;
pub mod mem;
pub mod policy;
pub mod show;
pub mod registry;
pub mod inject;

#[cfg(test)]
#[path = "tests/stats.rs"]
mod tests;

pub use counters::{Counters, Shape};
pub use iostat::{info_body as iostat_info_body, Io, Iostat};
pub use inject::stats_body as inject_stats_body;
pub use mem::Footprint;
pub use registry::{register, status_body, status_show, unregister,
                   PartFn, STATUS_DIR, STATUS_NAME, STATUS_PATH};
pub use sample::General;
pub use show::partition;
