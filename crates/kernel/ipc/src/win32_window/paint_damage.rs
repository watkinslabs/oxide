//! Canonical exact update regions and paint-state transitions (`31fl§5`).
use super::{WindowError, WindowRect};
use crate::win32_gdi::{COMPLEX_REGION, NULL_REGION, SIMPLE_REGION};
use alloc::vec::Vec;

#[path = "paint_damage/region.rs"]
mod region;
pub use region::PaintRegion;

#[path = "paint_damage/state.rs"]
mod state;
pub use state::*;

#[path = "paint_damage/owner.rs"]
mod owner;
#[path = "paint_damage/update.rs"]
mod update;
pub use update::region_complexity;
#[path = "paint_damage/tree.rs"]
mod tree;
#[path = "paint_damage/readiness.rs"]
mod readiness;
#[path = "paint_damage/parents.rs"]
mod parents;
#[path = "paint_damage/visible.rs"]
mod visible;
#[cfg(test)]
#[path = "paint_damage/tests.rs"]
mod tests;
