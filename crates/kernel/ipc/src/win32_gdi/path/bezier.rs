//! Recursive midpoint subdivision of cubic Bezier segments into polylines; 31fk§8.
//! Subdivision runs on coordinates shifted up four bits, so rounding matches the flattened output.
use super::{Vec, GdiError};
use crate::win32_gdi::region::scan::Point;

const SHIFT_BITS: u32 = 4;
const PIXEL: i64 = 1 << SHIFT_BITS;
const MAX_DEPTH: u32 = 8;
const MAX_OUTPUT: usize = 1 << 16;

fn up(value: i32) -> i64 { i64::from(value) << SHIFT_BITS }
fn down(value: i64) -> i64 { (value + (1 << (SHIFT_BITS - 1))) >> SHIFT_BITS }
fn middle(a: (i64, i64), b: (i64, i64)) -> (i64, i64) { ((a.0 + b.0 + 1) / 2, (a.1 + b.1 + 1) / 2) }

/// Control points inside the chord and within one pixel of it end subdivision. # C: O(1)
fn flat_enough(p: &[(i64, i64); 4]) -> bool {
    let (dx, dy) = (p[3].0 - p[0].0, p[3].1 - p[0].1);
    if dy.abs() <= dx.abs() {
        if !between(p[1].0, p[0].0, p[3].0) || !between(p[2].0, p[0].0, p[3].0) { return false; }
        let dx = down(dx);
        if dx == 0 { return true; }
        (p[1].1 - p[0].1 - (dy / dx) * down(p[1].0 - p[0].0)).abs() <= PIXEL
            && (p[2].1 - p[0].1 - (dy / dx) * down(p[2].0 - p[0].0)).abs() <= PIXEL
    } else {
        if !between(p[1].1, p[0].1, p[3].1) || !between(p[2].1, p[0].1, p[3].1) { return false; }
        let dy = down(dy);
        if dy == 0 { return true; }
        (p[1].0 - p[0].0 - (dx / dy) * down(p[1].1 - p[0].1)).abs() <= PIXEL
            && (p[2].0 - p[0].0 - (dx / dy) * down(p[2].1 - p[0].1)).abs() <= PIXEL
    }
}

/// A control coordinate must lie between the chord endpoints on the major axis. # C: O(1)
fn between(value: i64, start: i64, end: i64) -> bool { if value < start { value >= end } else { value <= end } }

fn emit(out: &mut Vec<Point>, value: (i64, i64)) -> Result<(), GdiError> {
    if out.len() >= MAX_OUTPUT { return Err(GdiError::HandleLimit); }
    out.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
    out.push(Point { x: down(value.0) as i32, y: down(value.1) as i32 }); Ok(())
}

fn subdivide(mut p: [(i64, i64); 4], out: &mut Vec<Point>, level: u32) -> Result<(), GdiError> {
    if level == 0 || flat_enough(&p) {
        if out.is_empty() { emit(out, p[0])?; }
        return emit(out, p[3]);
    }
    let mut second = [(0i64, 0i64); 4];
    second[3] = p[3];
    second[2] = middle(p[2], p[3]);
    second[0] = middle(p[1], p[2]);
    second[1] = middle(second[0], second[2]);
    p[1] = middle(p[0], p[1]);
    p[2] = middle(p[1], second[0]);
    p[3] = middle(p[2], second[1]);
    second[0] = p[3];
    subdivide(p, out, level - 1)?;
    subdivide(second, out, level - 1)
}

/// Flatten 3n+1 control points into the polyline that approximates them. # C: O(output points)
pub fn flatten(points: &[Point]) -> Result<Vec<Point>, GdiError> {
    if points.is_empty() || (points.len() - 1) % 3 != 0 { return Err(GdiError::InvalidDimensions); }
    let mut out: Vec<Point> = Vec::new();
    for segment in 0..(points.len() - 1) / 3 {
        let mut buffer = [(0i64, 0i64); 4];
        for (slot, point) in buffer.iter_mut().zip(&points[segment * 3..segment * 3 + 4]) { *slot = (up(point.x), up(point.y)); }
        subdivide(buffer, &mut out, MAX_DEPTH)?;
    }
    Ok(out)
}

#[cfg(test)]
#[path = "../tests/path_bezier.rs"]
mod tests;
