//! Integer scanline conversion of poly-polygons into exact region coverage; 31fk§6.
//! Edges advance by the midpoint form with y as the major axis; horizontal edges are dropped.
use super::{Vec, WindowRect, GdiError};
use crate::win32_window::PaintRegion;

/// Scan conversion is bounded so an unbounded polygon cannot occupy the owner lock.
const MAX_SCANLINES: i64 = 1 << 16;
pub const ALTERNATE: i32 = 1;
pub const WINDING: i32 = 2;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Point { pub x: i32, pub y: i32 }

#[derive(Clone, Copy, Debug, Default)]
struct Bres { minor_axis: i32, d: i64, m: i32, m1: i32, incr1: i64, incr2: i64 }

impl Bres {
    /// Half-pixel bias differs by edge direction so left edges flip a pixel later. # C: O(1)
    fn init(dy: i32, x1: i32, x2: i32) -> Self {
        let mut out = Self { minor_axis: x1, ..Self::default() };
        if dy == 0 { return out; }
        let (dx, dy64) = (i64::from(x2) - i64::from(x1), i64::from(dy));
        if dx < 0 {
            out.m = (dx / dy64) as i32; out.m1 = out.m.wrapping_sub(1);
            out.incr1 = -2 * dx + 2 * dy64 * i64::from(out.m1);
            out.incr2 = -2 * dx + 2 * dy64 * i64::from(out.m);
            out.d = 2 * i64::from(out.m) * dy64 - 2 * dx - 2 * dy64;
        } else {
            out.m = (dx / dy64) as i32; out.m1 = out.m.wrapping_add(1);
            out.incr1 = 2 * dx - 2 * dy64 * i64::from(out.m1);
            out.incr2 = 2 * dx - 2 * dy64 * i64::from(out.m);
            out.d = -2 * i64::from(out.m) * dy64 + 2 * dx;
        }
        out
    }
    /// # C: O(1)
    fn step(&mut self) {
        let take_m1 = if self.m1 > 0 { self.d > 0 } else { self.d >= 0 };
        if take_m1 { self.minor_axis = self.minor_axis.wrapping_add(self.m1); self.d = self.d.wrapping_add(self.incr1); }
        else { self.minor_axis = self.minor_axis.wrapping_add(self.m); self.d = self.d.wrapping_add(self.incr2); }
    }
}

#[derive(Clone, Copy, Debug)]
struct Edge { ymax: i32, bres: Bres, clockwise: bool }

struct EdgeTable { edges: Vec<Edge>, buckets: Vec<(i32, Vec<usize>)>, ymin: i32, ymax: i32 }

fn push<T>(out: &mut Vec<T>, value: T) -> Result<(), GdiError> {
    out.try_reserve(1).map_err(|_| GdiError::HandleLimit)?; out.push(value); Ok(())
}

fn insert<T>(out: &mut Vec<T>, index: usize, value: T) -> Result<(), GdiError> {
    out.try_reserve(1).map_err(|_| GdiError::HandleLimit)?; out.insert(index, value); Ok(())
}

/// Bucket edges by entry scanline, each bucket ordered by starting minor axis. # C: O(N_points²)
fn build_edge_table(points: &[Point], counts: &[usize]) -> Result<EdgeTable, GdiError> {
    let mut table = EdgeTable { edges: Vec::new(), buckets: Vec::new(), ymin: i32::MAX, ymax: i32::MIN };
    let mut base = 0usize;
    for count in counts {
        let count = *count;
        if base + count > points.len() { return Err(GdiError::InvalidDimensions); }
        let polygon = &points[base..base + count];
        base += count;
        if count < 2 { continue; }
        let mut previous = polygon[count - 1];
        for current in polygon {
            let current = *current;
            let (top, bottom, clockwise) = if previous.y > current.y { (current, previous, false) } else { (previous, current, true) };
            previous = current;
            if bottom.y == top.y { continue; }
            let dy = bottom.y.wrapping_sub(top.y);
            let edge = Edge { ymax: bottom.y - 1, bres: Bres::init(dy, top.x, bottom.x), clockwise };
            let index = table.edges.len();
            push(&mut table.edges, edge)?;
            let bucket = match table.buckets.binary_search_by_key(&top.y, |entry| entry.0) {
                Ok(found) => found,
                Err(slot) => { insert(&mut table.buckets, slot, (top.y, Vec::new()))?; slot },
            };
            let minor = table.edges[index].bres.minor_axis;
            let list = &mut table.buckets[bucket].1;
            let at = list.iter().position(|other| table.edges[*other].bres.minor_axis >= minor).unwrap_or(list.len());
            insert(list, at, index)?;
            table.ymin = table.ymin.min(top.y);
            table.ymax = table.ymax.max(bottom.y);
        }
    }
    Ok(table)
}

/// Merge one entry bucket into the active table, keeping the minor-axis order. # C: O(N_active²)
fn load_active(active: &mut Vec<usize>, edges: &[Edge], bucket: &[usize]) -> Result<(), GdiError> {
    for entry in bucket {
        let minor = edges[*entry].bres.minor_axis;
        let at = active.iter().position(|other| edges[*other].bres.minor_axis >= minor).unwrap_or(active.len());
        insert(active, at, *entry)?;
    }
    Ok(())
}

/// Retire finished edges, advance the rest, then restore minor-axis order. # C: O(N_active²)
fn next_scanline(active: &mut Vec<usize>, edges: &mut [Edge], y: i32) -> bool {
    let mut changed = false;
    let mut index = 0;
    while index < active.len() {
        let edge = active[index];
        if edges[edge].ymax == y { active.remove(index); changed = true; }
        else { edges[edge].bres.step(); index += 1; }
    }
    let mut index = 0;
    while index < active.len() {
        let entry = active[index];
        let minor = edges[entry].bres.minor_axis;
        let mut at = 0;
        while at < active.len() {
            if active[at] == entry { break; }
            if edges[active[at]].bres.minor_axis > minor { break; }
            at += 1;
        }
        if active[at] == entry { index += 1; continue; }
        active.remove(index); active.insert(at, entry); changed = true; index += 1;
    }
    changed
}

/// Winding order links only the active edges that bound an interior span. # C: O(N_active)
fn winding_spans(active: &[usize], edges: &[Edge], out: &mut Vec<usize>) {
    out.clear();
    let mut inside = true;
    let mut depth = 0i32;
    for entry in active {
        if edges[*entry].clockwise { depth += 1; } else { depth -= 1; }
        if (!inside && depth == 0) || (inside && depth != 0) { out.push(*entry); inside = !inside; }
    }
}

struct Spans { rects: Vec<WindowRect>, scratch: WindowRect, first: bool }

impl Spans {
    /// Alternate parity opens a span on the first edge and closes it on the second. # C: O(1) amortized
    fn alternate(&mut self, minor: i32, y: i32) -> Result<(), GdiError> {
        if self.first { self.scratch = WindowRect { left: minor, top: y, right: minor, bottom: y + 1 }; }
        else if self.scratch.left != minor {
            let merge = self.rects.last().is_some_and(|last| last.top == y && last.right >= self.scratch.left);
            if !merge { let scratch = self.scratch; push(&mut self.rects, scratch)?; }
            if let Some(last) = self.rects.last_mut() { last.right = minor; }
        }
        self.first = !self.first;
        Ok(())
    }
    /// Winding spans commit one whole-scanline rectangle per interior interval. # C: O(1) amortized
    fn winding(&mut self, minor: i32, y: i32) -> Result<(), GdiError> {
        if self.first { self.scratch = WindowRect { left: minor, top: y, right: minor, bottom: y + 1 }; }
        else if self.scratch.left != minor {
            self.scratch.right = minor; self.scratch.bottom = y + 1;
            let scratch = self.scratch; push(&mut self.rects, scratch)?;
        }
        self.first = !self.first;
        Ok(())
    }
}

/// Scan convert closed polygons into exact coverage under the given fill mode. # C: O(height * N_active²)
pub fn poly_polygon_region(points: &[Point], counts: &[usize], mode: i32) -> Result<PaintRegion, GdiError> {
    if let Some(rect) = axis_aligned_rectangle(points, counts) {
        return PaintRegion::from_rect(rect).map_err(|_| GdiError::HandleLimit);
    }
    let mut table = build_edge_table(points, counts)?;
    if table.edges.is_empty() { return Ok(PaintRegion::default()); }
    if i64::from(table.ymax) - i64::from(table.ymin) > MAX_SCANLINES { return Err(GdiError::HandleLimit); }
    let mut active: Vec<usize> = Vec::new();
    let mut winding: Vec<usize> = Vec::new();
    let mut spans = Spans { rects: Vec::new(), scratch: WindowRect { left: 0, top: 0, right: 0, bottom: 0 }, first: true };
    let mut bucket = 0usize;
    for y in table.ymin..table.ymax {
        if table.buckets.get(bucket).is_some_and(|entry| entry.0 == y) {
            let entries = core::mem::take(&mut table.buckets[bucket].1);
            load_active(&mut active, &table.edges, &entries)?;
            bucket += 1;
            if mode == WINDING { winding_spans(&active, &table.edges, &mut winding); }
        }
        if mode == WINDING {
            let mut next = 0usize;
            for entry in &active {
                if winding.get(next) != Some(entry) { continue; }
                next += 1;
                spans.winding(table.edges[*entry].bres.minor_axis, y)?;
            }
        } else {
            for entry in &active { spans.alternate(table.edges[*entry].bres.minor_axis, y)?; }
        }
        if next_scanline(&mut active, &mut table.edges, y) && mode == WINDING {
            winding_spans(&active, &table.edges, &mut winding);
        }
    }
    PaintRegion::from_rects(&spans.rects).map_err(|_| GdiError::HandleLimit)
}

/// One four- or five-point axis-aligned closed polygon is stored as a plain rectangle. # C: O(1)
fn axis_aligned_rectangle(points: &[Point], counts: &[usize]) -> Option<WindowRect> {
    if counts.len() != 1 { return None; }
    let count = counts[0];
    if points.len() < count { return None; }
    let closed = count == 5 && points[4] == points[0];
    if count != 4 && !closed { return None; }
    let p = &points[..4];
    let horizontal = p[0].y == p[1].y && p[1].x == p[2].x && p[2].y == p[3].y && p[3].x == p[0].x;
    let vertical = p[0].x == p[1].x && p[1].y == p[2].y && p[2].x == p[3].x && p[3].y == p[0].y;
    if !(horizontal || vertical) { return None; }
    Some(WindowRect { left: p[0].x.min(p[2].x), top: p[0].y.min(p[2].y), right: p[0].x.max(p[2].x), bottom: p[0].y.max(p[2].y) })
}

#[cfg(test)]
#[path = "../tests/region_scan.rs"]
mod tests;
