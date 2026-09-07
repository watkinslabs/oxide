//! Module manifest: canonical HRGN owner.
//! `objects` holds handle lifetime and combine, `bands` the canonical y-x band form,
//! `shapes` rounded and elliptic construction, `query` predicates and RGNDATA,
//! `scan` polygon scan conversion, `raster` region drawing into a device context.
use super::{GdiError, GdiManager, Rect};
use crate::win32_window::WindowRect;
use alloc::vec::Vec;

#[path = "region/objects.rs"]
mod objects;
#[path = "region/bands.rs"]
pub mod bands;
#[path = "region/shapes.rs"]
pub mod shapes;
#[path = "region/query.rs"]
pub mod query;
#[path = "region/scan.rs"]
pub mod scan;
#[path = "region/raster.rs"]
mod raster;

pub use objects::{TYPE_REGION, RGN_AND, RGN_COPY, RGN_DIFF, RGN_OR, RGN_XOR};
