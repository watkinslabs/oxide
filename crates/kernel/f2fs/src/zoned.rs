//! Volumes whose segment placement is dictated by a drive's zones.
//!
//! A zoned drive divides its blocks into zones; a sequential zone accepts
//! writes only at its write pointer, and may present a CAPACITY smaller than
//! its length, so the blocks between the two exist in the address space and
//! can never be written. The filesystem's job is to know which blocks those
//! are and never place anything there.
//!
//! Every figure here comes from the DRIVE's own zone report. None of it is
//! inferred from the superblock, from the zone size the format assumes, or
//! from a default: a zone map that disagrees with the drive is not a
//! performance problem, it is a filesystem that writes where the drive will
//! refuse or, on a host-aware drive, where it will silently relocate. A drive
//! that reports nothing is treated as having no sequential zones at all,
//! which is exactly what a conventional drive is.
//!
//! Module manifest:
//! - `report`:  what a drive says about its zones.
//! - `geom`:    the per-volume figures those reports settle.
//! - `usable`:  how much of a segment and a section may actually be written.
//! - `wp`:      reconciling the drive's write pointers with the segment tables.
//! - `discard`: what announcing a freed run means when the run is in a zone.
//!
//! The mount options a zoned volume forces or refuses are NOT here: they are
//! decided with every other option-consistency rule, against the same feature
//! word, in `consistency`.

pub mod report;
pub mod geom;
pub mod usable;
pub mod wp;
pub mod discard;

pub use report::{DevZones, Zone, ZoneCond, ZoneType};
pub use geom::{Geometry, ZoneError};

#[cfg(test)]
#[path = "tests/zoned/mod.rs"]
mod tests;
