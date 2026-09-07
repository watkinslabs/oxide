//! Cubic curve flattening by recursive subdivision.
//!
//! Coordinates are shifted up four bits during subdivision so the midpoints
//! stay exact, and shifted back down with rounding when a segment is emitted.
use alloc::vec::Vec;
use super::{GdiError, Point};

/// Fractional bits the subdivision works in.
const SHIFT_BITS: u32 = 4;
/// One whole pixel in the shifted coordinate space.
const PIXEL: i64 = 1 << SHIFT_BITS;
/// Recursion depth at which a segment is emitted whatever its flatness.
const MAX_DEPTH: u32 = 8;

fn up(value: i32) -> i64 { i64::from(value) << SHIFT_BITS }
fn down(value: i64) -> i64 { (value + (1 << (SHIFT_BITS - 1))) >> SHIFT_BITS }
fn middle(a: (i64, i64), b: (i64, i64)) -> (i64, i64) { ((a.0 + b.0 + 1) / 2, (a.1 + b.1 + 1) / 2) }

/// Whether the four control points are flat enough to be one straight segment.
/// The control points must lie between the endpoints along the major axis, and
/// off the chord by at most one pixel. # C: O(1)
fn flat_enough(points: &[(i64, i64); 4]) -> bool {
    let dx = points[3].0 - points[0].0;
    let dy = points[3].1 - points[0].1;
    let between = |value: i64, first: i64, last: i64| if value < first { value >= last } else { value <= last };
    if dy.abs() <= dx.abs() {
        if !between(points[1].0, points[0].0, points[3].0) || !between(points[2].0, points[0].0, points[3].0) { return false; }
        let dx = down(dx);
        if dx == 0 { return true; }
        let slope = dy / dx;
        (points[1].1 - points[0].1 - slope * down(points[1].0 - points[0].0)).abs() <= PIXEL
            && (points[2].1 - points[0].1 - slope * down(points[2].0 - points[0].0)).abs() <= PIXEL
    } else {
        if !between(points[1].1, points[0].1, points[3].1) || !between(points[2].1, points[0].1, points[3].1) { return false; }
        let dy = down(dy);
        if dy == 0 { return true; }
        let slope = dx / dy;
        (points[1].0 - points[0].0 - slope * down(points[1].1 - points[0].1)).abs() <= PIXEL
            && (points[2].0 - points[0].0 - slope * down(points[2].1 - points[0].1)).abs() <= PIXEL
    }
}

fn subdivide(points: [(i64, i64); 4], out: &mut Vec<Point>, level: u32) -> Result<(), GdiError> {
    if level == 0 || flat_enough(&points) {
        out.try_reserve(2).map_err(|_| GdiError::HandleLimit)?;
        if out.is_empty() { out.push(Point { x: down(points[0].0) as i32, y: down(points[0].1) as i32 }); }
        out.push(Point { x: down(points[3].0) as i32, y: down(points[3].1) as i32 });
        return Ok(());
    }
    let mut first = points;
    let mut second = [(0i64, 0i64); 4];
    second[3] = points[3];
    second[2] = middle(points[2], points[3]);
    second[0] = middle(points[1], points[2]);
    second[1] = middle(second[0], second[2]);
    first[1] = middle(points[0], points[1]);
    first[2] = middle(first[1], second[0]);
    first[3] = middle(first[2], second[1]);
    second[0] = first[3];
    subdivide(first, out, level - 1)?;
    subdivide(second, out, level - 1)
}

/// Flatten a run of `3n + 1` control points into the polyline that approximates
/// it. A run of any other length has no curve to flatten. # C: O(N_segments)
pub fn flatten_bezier(points: &[Point]) -> Result<Vec<Point>, GdiError> {
    if points.len() < 4 || (points.len() - 1) % 3 != 0 { return Err(GdiError::InvalidDimensions); }
    let mut out = Vec::new();
    for curve in 0..(points.len() - 1) / 3 {
        let mut control = [(0i64, 0i64); 4];
        for (index, slot) in control.iter_mut().enumerate() {
            let point = points[curve * 3 + index];
            *slot = (up(point.x), up(point.y));
        }
        subdivide(control, &mut out, MAX_DEPTH)?;
    }
    Ok(out)
}

#[cfg(test)]
#[path = "tests/bezier.rs"]
mod tests;
