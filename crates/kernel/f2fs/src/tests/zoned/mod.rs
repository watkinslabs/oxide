//! What a drive's zone report settles, and what it forbids.
//!
//! - `geom`:   the figures the reports agree on, and the disagreements.
//! - `usable`: how much of a segment and a section may be written.
//! - `mount`:  a zoned volume brought up against real reports.

#[path = "geom.rs"]
mod geom;
#[path = "usable.rs"]
mod usable;
#[path = "mount.rs"]
mod mount;
