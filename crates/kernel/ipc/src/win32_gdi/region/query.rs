//! Region predicates and RGNDATA serialization over canonical band coverage; 31fk§6.
use super::{bands, Vec, WindowRect, GdiError, Rect};
use crate::win32_window::PaintRegion;

pub const RDH_RECTANGLES: u32 = 1;
pub const RGNDATAHEADER_BYTES: usize = 32;
const RECT_BYTES: usize = 16;

/// Half-open coverage test: right and bottom edges are outside the region. # C: O(N_rects)
pub fn pt_in_region(region: &PaintRegion, x: i32, y: i32) -> bool {
    region.rects().iter().any(|r| r.right > x && r.left <= x && r.bottom > y && r.top <= y)
}

/// Any overlap with the ordered rectangle, not containment. # C: O(N_rects)
pub fn rect_in_region(region: &PaintRegion, rect: Rect) -> bool {
    let (left, right) = if rect.left > rect.right { (rect.right, rect.left) } else { (rect.left, rect.right) };
    let (top, bottom) = if rect.top > rect.bottom { (rect.bottom, rect.top) } else { (rect.top, rect.bottom) };
    region.rects().iter().any(|r| r.left < right && r.right > left && r.top < bottom && r.bottom > top)
}

/// Identity compares canonical bands, so equal coverage compares equal. # C: O(N_rects² log N_rects)
pub fn equal_region(first: &PaintRegion, second: &PaintRegion) -> Result<bool, GdiError> {
    Ok(bands::canonical(first)? == bands::canonical(second)?)
}

/// Translation of every rectangle; an out-of-range shift fails without mutating. # C: O(N_rects)
pub fn offset_region(region: &PaintRegion, x: i32, y: i32) -> Result<PaintRegion, GdiError> {
    region.translated(x, y).map_err(|_| GdiError::HandleLimit)
}

/// Frame coverage is the source minus its four-way inward intersection. # C: O(N_rects² * fragments)
pub fn frame_region(region: &PaintRegion, x: i32, y: i32) -> Result<PaintRegion, GdiError> {
    if region.is_empty() { return Err(GdiError::NoSuchObject); }
    let mut inner = offset_region(region, x.wrapping_neg(), 0)?;
    for shift in [(x, 0), (0, y.wrapping_neg()), (0, y)] {
        let other = offset_region(region, shift.0, shift.1)?;
        intersect_into(&mut inner, &other)?;
    }
    let mut frame = region.try_copy().map_err(|_| GdiError::HandleLimit)?;
    frame.subtract(&inner).map_err(|_| GdiError::HandleLimit)?;
    Ok(frame)
}

/// Exact intersection expressed as a double subtraction of the outside coverage. # C: O(N_rects² * fragments)
pub fn intersect_into(left: &mut PaintRegion, right: &PaintRegion) -> Result<(), GdiError> {
    let mut outside = left.try_copy().map_err(|_| GdiError::HandleLimit)?;
    outside.subtract(right).map_err(|_| GdiError::HandleLimit)?;
    left.subtract(&outside).map_err(|_| GdiError::HandleLimit)
}

/// Byte size of the RGNDATA a region serializes into, header included. # C: O(N_rects² log N_rects)
pub fn region_data_size(bands: &[WindowRect]) -> usize { RGNDATAHEADER_BYTES + bands.len() * RECT_BYTES }

/// Serialize canonical bands as an RDH_RECTANGLES RGNDATA image. # C: O(N_bands)
pub fn region_data_bytes(region: &PaintRegion) -> Result<Vec<u8>, GdiError> {
    let bands = bands::canonical(region)?;
    let mut out: Vec<u8> = Vec::new();
    out.try_reserve(region_data_size(&bands)).map_err(|_| GdiError::HandleLimit)?;
    let bound = bands::extents(&bands).unwrap_or(WindowRect { left: 0, top: 0, right: 0, bottom: 0 });
    let size = (bands.len() * RECT_BYTES) as u32;
    for word in [RGNDATAHEADER_BYTES as u32, RDH_RECTANGLES, bands.len() as u32, size] { out.extend_from_slice(&word.to_le_bytes()); }
    for value in [bound.left, bound.top, bound.right, bound.bottom] { out.extend_from_slice(&value.to_le_bytes()); }
    for rect in &bands {
        for value in [rect.left, rect.top, rect.right, rect.bottom] { out.extend_from_slice(&value.to_le_bytes()); }
    }
    Ok(out)
}

/// Rebuild a region from the rectangle array of an RGNDATA image. # C: O(N_rects²)
pub fn region_from_data(bytes: &[u8]) -> Result<PaintRegion, GdiError> {
    if bytes.len() < RGNDATAHEADER_BYTES { return Err(GdiError::InvalidDimensions); }
    let word = |offset: usize| u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]);
    let value = |offset: usize| word(offset) as i32;
    if word(0) < RGNDATAHEADER_BYTES as u32 { return Err(GdiError::InvalidDimensions); }
    let count = word(8) as usize;
    let available = (bytes.len() - RGNDATAHEADER_BYTES) / RECT_BYTES;
    if count > available { return Err(GdiError::InvalidDimensions); }
    let mut rects: Vec<WindowRect> = Vec::new();
    rects.try_reserve(count).map_err(|_| GdiError::HandleLimit)?;
    for index in 0..count {
        let base = RGNDATAHEADER_BYTES + index * RECT_BYTES;
        let rect = WindowRect { left: value(base), top: value(base + 4), right: value(base + 8), bottom: value(base + 12) };
        if rect.left < rect.right && rect.top < rect.bottom { rects.push(rect); }
    }
    PaintRegion::from_rects(&rects).map_err(|_| GdiError::HandleLimit)
}

#[cfg(test)]
#[path = "../tests/region_query.rs"]
mod tests;
