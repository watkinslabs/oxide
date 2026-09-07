//! Rounded-rectangle and elliptic region rasterization; 31fk§6.
//! Corner arcs use the integer midpoint form, so no floating point enters region geometry.
use super::{Vec, WindowRect, GdiError};
use crate::win32_window::PaintRegion;

/// Windows region covers the rectangle interior, excluding right and bottom edges. # C: O(1)
fn ordered(left: i32, top: i32, right: i32, bottom: i32) -> (i32, i32, i32, i32) {
    let (left, right) = if left > right { (right, left) } else { (left, right) };
    let (top, bottom) = if top > bottom { (bottom, top) } else { (top, bottom) };
    (left, top, right, bottom)
}

/// Scanline spans of a rounded rectangle; empty when the shape degenerates to a rectangle. # C: O(ellipse_height)
pub fn round_rect_rects(left: i32, top: i32, right: i32, bottom: i32, ellipse_width: i32, ellipse_height: i32)
    -> Result<Vec<WindowRect>, GdiError> {
    let (left, top, right, bottom) = ordered(left, top, right, bottom);
    let (right, bottom) = (right.wrapping_sub(1), bottom.wrapping_sub(1));
    let width = (right - left).min(ellipse_width.saturating_abs());
    let height = (bottom - top).min(ellipse_height.saturating_abs());
    let mut out: Vec<WindowRect> = Vec::new();
    if width < 2 || height < 2 {
        if left < right && top < bottom {
            out.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
            out.push(WindowRect { left, top, right, bottom });
        }
        return Ok(out);
    }
    let count = height as usize;
    out.try_reserve(count).map_err(|_| GdiError::HandleLimit)?;
    for _ in 0..count { out.push(WindowRect { left: 0, top: 0, right: 0, bottom: 0 }); }
    let a = i64::from(width - 1);
    let b = i64::from(height - 1);
    let (asq, bsq) = (8 * a * a, 8 * b * b);
    let mut dx = 4 * b * b * (1 - a);
    let mut dy = 4 * a * a * (1 + (b % 2));
    let mut err = dx + dy + a * a * (b % 2);
    let (mut x, mut y) = (0i32, height / 2);
    out[y as usize].left = left; out[y as usize].right = right;
    while x <= width / 2 {
        let e2 = 2 * err;
        if e2 >= dx { x += 1; dx += bsq; err += dx; }
        if e2 <= dy {
            y += 1; dy += asq; err += dy;
            // The midpoint walk fills one span per half-height step; a stored count
            // that cannot hold the next span means the shape is already complete.
            let Some(slot) = out.get_mut(y as usize) else { break; };
            slot.left = left + x; slot.right = right - x;
        }
    }
    let half = height / 2;
    for index in 0..half as usize {
        let mirror = out[(b as usize) - index];
        let slot = &mut out[index];
        slot.left = mirror.left; slot.right = mirror.right;
        slot.top = top + index as i32; slot.bottom = slot.top + 1;
    }
    for index in half as usize..count {
        let slot = &mut out[index];
        slot.top = bottom - height + index as i32; slot.bottom = slot.top + 1;
    }
    out[half as usize].top = top + half;
    Ok(out)
}

/// Rounded rectangle as one exact region; degenerate corners produce the plain rectangle. # C: O(ellipse_height)
pub fn round_rect_region(left: i32, top: i32, right: i32, bottom: i32, ellipse_width: i32, ellipse_height: i32)
    -> Result<PaintRegion, GdiError> {
    let rects = round_rect_rects(left, top, right, bottom, ellipse_width, ellipse_height)?;
    PaintRegion::from_rects(&rects).map_err(|_| GdiError::HandleLimit)
}

/// Ellipse inscribed in the bounding rectangle is the full-corner rounded rectangle. # C: O(height)
pub fn elliptic_region(left: i32, top: i32, right: i32, bottom: i32) -> Result<PaintRegion, GdiError> {
    round_rect_region(left, top, right, bottom, right.wrapping_sub(left), bottom.wrapping_sub(top))
}

#[cfg(test)]
#[path = "../tests/region_shapes.rs"]
mod tests;
