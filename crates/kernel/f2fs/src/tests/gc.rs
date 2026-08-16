//! Segment cleaning.
//!
//! Module manifest:
//! - `victim`:   costing and choosing a victim, over a table with no medium.
//! - `liveness`: the three records a block's liveness is read from.
//! - `clean`:    cleaning a real volume, proved by remounting it.

#[path = "gc/victim.rs"]
mod victim;
#[path = "gc/liveness.rs"]
mod liveness;
#[path = "gc/clean.rs"]
mod clean;
