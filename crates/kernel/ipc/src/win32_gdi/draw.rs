//! Curved and multi-segment drawing primitives; 31fk§8.
//!
//! Module manifest:
//! - `geometry`: the integer ellipse, arc and rounded-rectangle point runs.
//! - `bezier`: cubic curve flattening.
//! - `fill`: scanline interior coverage for a closed point run.
//! - `render`: device-context entry points that stroke and fill those runs.

use super::{GdiError, GdiManager, Point, Rect};

#[path = "draw/geometry.rs"]
mod geometry;
pub use geometry::{ellipse_first_quadrant, arc_points, round_rect_points};
#[path = "draw/bezier.rs"]
mod bezier;
pub use bezier::flatten_bezier;
#[path = "draw/fill.rs"]
mod fill;
pub use fill::{fill_polygon, ALTERNATE, WINDING};
#[path = "draw/render.rs"]
mod render;
pub use render::{ARC, ARC_TO, CHORD, PIE, POLY_POLYGON, POLY_POLYLINE, POLY_BEZIER,
    POLY_BEZIER_TO, POLYLINE_TO, POLY_POLYGON_RGN, PT_MOVETO, PT_LINETO, PT_BEZIERTO, PT_CLOSEFIGURE};
