//! Pattern-brush realization: one immutable bitmap copy becomes tiled XRGB cells.
use alloc::vec::Vec;
use super::super::{GdiError, MAX_SURFACE_PIXELS};
use super::super::bitmap::BitmapPattern;
use super::BrushStyle;

/// The three DC colors a brush can consume, XRGB. A bound client mirrors them
/// in shared memory, so the caller supplies them rather than the owner reading
/// a private copy that the client may already have replaced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedDcColors { pub brush: u32, pub text: u32, pub background: u32, pub background_mode: u32 }

/// A hatch cell is eight pixels square.
const HATCH_EXTENT: i32 = 8;
/// Background mode that paints the gaps between hatch lines.
pub const OPAQUE: u32 = 2;
/// Hatch styles, in the order the caller names them.
pub const HS_HORIZONTAL: u32 = 0;
pub const HS_DIAGCROSS: u32 = 5;
/// A style past the last named one but inside the interface range becomes a
/// solid brush; anything beyond is refused.
pub const HS_API_MAX: u32 = 12;

/// The eight rows of one hatch cell, most significant bit leftmost. # C: O(1)
pub fn hatch_rows(style: u32) -> Option<[u8; 8]> {
    Some(match style {
        HS_HORIZONTAL => [0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00],
        1 => [0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08],
        2 => [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01],
        3 => [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80],
        4 => [0x08, 0x08, 0x08, 0xff, 0x08, 0x08, 0x08, 0x08],
        HS_DIAGCROSS => [0x81, 0x42, 0x24, 0x18, 0x18, 0x24, 0x42, 0x81],
        _ => return None,
    })
}

/// Realized brush pixels. A pattern is expanded once per operation because a
/// monochrome device-dependent pattern resolves against the destination DC's
/// text and background colors, which change between operations.
pub enum Fill { Uniform(u32), Tiled { width: i32, height: i32, cells: Vec<u32> },
    /// Eight rows of eight one-bit cells: a set bit takes the brush colour, a
    /// clear one the background, or nothing at all when the destination's
    /// background mode is transparent.
    Hatch { rows: [u8; 8], color: u32, background: Option<u32> } }

impl Fill {
    /// Brush origin is the device origin, so a tile repeats on its own extent.
    /// # C: O(1)
    pub fn color(&self, x: i32, y: i32) -> Option<u32> {
        match self {
            Self::Uniform(color) => Some(*color),
            Self::Tiled { width, height, cells } => {
                let index = (y.rem_euclid(*height) as usize) * (*width as usize) + x.rem_euclid(*width) as usize;
                Some(cells.get(index).copied().unwrap_or(0))
            }
            Self::Hatch { rows, color, background } => {
                let row = rows[y.rem_euclid(HATCH_EXTENT) as usize];
                if row >> (7 - x.rem_euclid(HATCH_EXTENT)) & 1 != 0 { Some(*color) } else { *background }
            }
        }
    }
}

/// Realize before any destination pixel is touched: an unresolvable pattern
/// depth fails the whole operation instead of painting part of it.
/// # C: O(pattern pixels)
pub fn fill(style: BrushStyle, pattern: Option<&BitmapPattern>, colors: SharedDcColors) -> Result<Fill, GdiError> {
    match style {
        BrushStyle::Solid(color) => Ok(Fill::Uniform(color)),
        BrushStyle::Hollow => Ok(Fill::Uniform(0)),
        BrushStyle::Hatch { style, color } => Ok(Fill::Hatch { rows: hatch_rows(style).ok_or(GdiError::InvalidDimensions)?,
            color, background: (colors.background_mode == OPAQUE).then_some(colors.background) }),
        BrushStyle::Pattern => {
            let pattern = pattern.ok_or(GdiError::NoSuchObject)?;
            let (width, height) = (pattern.width, pattern.height);
            let count = (width as usize).checked_mul(height as usize).ok_or(GdiError::InvalidDimensions)?;
            if width <= 0 || height <= 0 || count > MAX_SURFACE_PIXELS { return Err(GdiError::InvalidDimensions); }
            let mut cells = Vec::new();
            cells.try_reserve(count).map_err(|_| GdiError::HandleLimit)?;
            for y in 0..height { for x in 0..width {
                cells.push(pattern.pixel(x, y, colors.text, colors.background).ok_or(GdiError::InvalidDimensions)?);
            } }
            Ok(Fill::Tiled { width, height, cells })
        }
    }
}

#[cfg(test)]
#[path = "tests/pattern.rs"]
mod tests;
