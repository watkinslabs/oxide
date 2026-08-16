//! Segment cleaning.
//!
//! Module manifest:
//! - `victim`:   costing and choosing a victim, over a table with no medium.
//! - `search`:   bounded, resuming selection, in sections.
//! - `liveness`: the three records a block's liveness is read from.
//! - `clean`:    cleaning a real volume, proved by remounting it.
//! - `prefree`:  segments held back from the allocator until a checkpoint.
//! - `mtime`:    when a segment was written, and the policy that reads it.
//! - `flushdev`: emptying one member device of a spread volume onto the rest.

#[path = "gc/victim.rs"]
mod victim;
#[path = "gc/search.rs"]
mod search;
#[path = "gc/liveness.rs"]
mod liveness;
#[path = "gc/clean.rs"]
mod clean;
#[path = "gc/prefree.rs"]
mod prefree;
#[path = "gc/mtime.rs"]
mod mtime;
#[path = "gc/flushdev.rs"]
mod flushdev;
