//! Where a write lands.
//!
//! Module manifest:
//! - `ipu`: the two ladders that decide whether a page is rewritten in place.
//! - `ssr`: the pressure that decides whether a log recycles a segment.

mod ipu;
mod ssr;
