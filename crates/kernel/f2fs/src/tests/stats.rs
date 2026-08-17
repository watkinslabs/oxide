//! What the statistics surface must keep true.
//!
//! Module manifest:
//! - `counters`: that every pair of sites cancels, and that nothing wraps.
//! - `iostat`:   the rollups, the compressed twins, and the off switch.
//! - `sample`:   that the picture matches the volume it was taken from.
//! - `show`:     the report's exact text, which is the part tools depend on.
//! - `registry`: the list of mounts, and the numbering the report uses.
//! - `mem`:      that the footprint follows the structures it measures.
//! - `policy`:   the policy set and the condition list.
//! - `inject`:   one row per site, armed or not.

#[path = "stats/counters.rs"] mod counters;
#[path = "stats/iostat.rs"] mod iostat;
#[path = "stats/sample.rs"] mod sample;
#[path = "stats/show.rs"] mod show;
#[path = "stats/registry.rs"] mod registry;
#[path = "stats/mem.rs"] mod mem;
#[path = "stats/policy.rs"] mod policy;
#[path = "stats/inject.rs"] mod inject;
