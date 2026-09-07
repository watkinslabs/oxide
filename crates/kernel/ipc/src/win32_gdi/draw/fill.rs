//! Scanline interior coverage for a closed point run.
//!
//! A polygon's interior is the set of pixels the region owner would produce for
//! the same outline: for each scanline, the crossings of every non-horizontal
//! edge, ordered, and filled according to the polygon fill mode.
use alloc::vec::Vec;
use super::{GdiError, Point, Rect};

/// Fill between alternate crossing pairs.
pub const ALTERNATE: u32 = 1;
/// Fill wherever the accumulated edge direction is non-zero.
pub const WINDING: u32 = 2;

/// Emit every interior pixel of one closed point run, clipped to `clip`. The
/// run is closed implicitly: the last point joins the first. # C: O(clip height * N_points)
pub fn fill_polygon(points: &[Point], clip: Rect, mode: u32, mut emit: impl FnMut(i32, i32))
    -> Result<(), GdiError> {
    if points.len() < 3 || clip.left >= clip.right || clip.top >= clip.bottom { return Ok(()); }
    let mut crossings: Vec<(i64, i32)> = Vec::new();
    crossings.try_reserve(points.len()).map_err(|_| GdiError::HandleLimit)?;
    let (mut top, mut bottom) = (i64::from(i32::MAX), i64::from(i32::MIN));
    for point in points { top = top.min(i64::from(point.y)); bottom = bottom.max(i64::from(point.y)); }
    let first = top.max(i64::from(clip.top));
    let last = bottom.min(i64::from(clip.bottom));
    for y in first..last {
        crossings.clear();
        for index in 0..points.len() {
            let start = points[index];
            let end = points[(index + 1) % points.len()];
            let (y0, y1) = (i64::from(start.y), i64::from(end.y));
            if y0 == y1 { continue; }
            let (low, high, direction) = if y0 < y1 { (y0, y1, 1) } else { (y1, y0, -1) };
            if y < low || y >= high { continue; }
            let (x0, x1) = (i64::from(start.x), i64::from(end.x));
            crossings.push((x0 + (x1 - x0) * (y - y0) / (y1 - y0), direction));
        }
        crossings.sort_unstable();
        let mut depth = 0i32;
        let mut span_start = 0i64;
        for (index, (x, direction)) in crossings.iter().enumerate() {
            let inside_before = if mode == WINDING { depth != 0 } else { index % 2 == 1 };
            depth += direction;
            let inside_after = if mode == WINDING { depth != 0 } else { index % 2 == 0 };
            if !inside_before && inside_after { span_start = *x; }
            if inside_before && !inside_after {
                let from = span_start.max(i64::from(clip.left));
                let to = (*x).min(i64::from(clip.right));
                for pixel in from..to { emit(pixel as i32, y as i32); }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/fill.rs"]
mod tests;
