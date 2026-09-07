//! Canonical y-x banded coverage derived from exact disjoint region storage; 31fk§6.
//! Band form is what EqualRgn identity and RGNDATA rectangle counts observe.
use super::{Vec, WindowRect, GdiError};
use crate::win32_window::PaintRegion;

fn reserve<T>(out: &mut Vec<T>, extra: usize) -> Result<(), GdiError> { out.try_reserve(extra).map_err(|_| GdiError::HandleLimit) }

fn push<T>(out: &mut Vec<T>, value: T) -> Result<(), GdiError> { reserve(out, 1)?; out.push(value); Ok(()) }

/// Sorted distinct band boundaries taken from every rectangle edge. # C: O(N_rects²)
fn boundaries(rects: &[WindowRect]) -> Result<Vec<i32>, GdiError> {
    let mut out: Vec<i32> = Vec::new();
    for rect in rects {
        for edge in [rect.top, rect.bottom] {
            if let Err(index) = out.binary_search(&edge) { reserve(&mut out, 1)?; out.insert(index, edge); }
        }
    }
    Ok(out)
}

/// Merged x spans of every rectangle spanning one band, ordered left to right. # C: O(N_rects log N_rects)
fn band_spans(rects: &[WindowRect], top: i32, bottom: i32) -> Result<Vec<(i32, i32)>, GdiError> {
    let mut spans: Vec<(i32, i32)> = Vec::new();
    for rect in rects {
        if rect.top > top || rect.bottom < bottom { continue; }
        let span = (rect.left, rect.right);
        let index = spans.partition_point(|entry| entry.0 < span.0);
        reserve(&mut spans, 1)?; spans.insert(index, span);
    }
    let mut merged: Vec<(i32, i32)> = Vec::new();
    for span in spans {
        match merged.last_mut() {
            Some(last) if span.0 <= last.1 => last.1 = last.1.max(span.1),
            _ => push(&mut merged, span)?,
        }
    }
    Ok(merged)
}

/// Canonical band rectangles: top-to-bottom, left-to-right, x-coalesced, y-coalesced. # C: O(N_rects² log N_rects)
pub fn canonical(region: &PaintRegion) -> Result<Vec<WindowRect>, GdiError> {
    let rects = region.rects();
    let edges = boundaries(rects)?;
    let mut out: Vec<WindowRect> = Vec::new();
    let mut previous: Option<(usize, usize)> = None; // canonical index and rectangle count of the previous emitted band
    for pair in edges.windows(2) {
        let (top, bottom) = (pair[0], pair[1]);
        let spans = band_spans(rects, top, bottom)?;
        if spans.is_empty() { previous = None; continue; }
        if let Some((start, len)) = previous {
            if len == spans.len() && out[start..start + len].iter().zip(spans.iter())
                .all(|(rect, span)| rect.left == span.0 && rect.right == span.1) && out[start].bottom == top {
                for rect in &mut out[start..start + len] { rect.bottom = bottom; }
                continue;
            }
        }
        let start = out.len();
        let len = spans.len();
        for span in &spans { push(&mut out, WindowRect { left: span.0, top, right: span.1, bottom })?; }
        previous = Some((start, len));
    }
    Ok(out)
}

/// Bounding box of canonical bands; None only for empty coverage. # C: O(N_bands)
pub fn extents(bands: &[WindowRect]) -> Option<WindowRect> {
    let mut iter = bands.iter();
    let mut out = *iter.next()?;
    for rect in iter {
        out.left = out.left.min(rect.left); out.right = out.right.max(rect.right);
        out.top = out.top.min(rect.top); out.bottom = out.bottom.max(rect.bottom);
    }
    Some(out)
}

#[cfg(test)]
#[path = "../tests/region_bands.rs"]
mod tests;
