//! Pattern-brush realization: one immutable bitmap copy becomes tiled XRGB cells.
use alloc::vec::Vec;
use super::super::{GdiError, MAX_SURFACE_PIXELS};
use super::super::bitmap::BitmapPattern;
use super::BrushStyle;

/// The three DC colors a brush can consume, XRGB. A bound client mirrors them
/// in shared memory, so the caller supplies them rather than the owner reading
/// a private copy that the client may already have replaced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedDcColors { pub brush: u32, pub text: u32, pub background: u32 }

/// Realized brush pixels. A pattern is expanded once per operation because a
/// monochrome device-dependent pattern resolves against the destination DC's
/// text and background colors, which change between operations.
pub(super) enum Fill { Uniform(u32), Tiled { width: i32, height: i32, cells: Vec<u32> } }

impl Fill {
    /// Brush origin is the device origin, so a tile repeats on its own extent.
    /// # C: O(1)
    pub(super) fn color(&self, x: i32, y: i32) -> u32 {
        match self {
            Self::Uniform(color) => *color,
            Self::Tiled { width, height, cells } => {
                let index = (y.rem_euclid(*height) as usize) * (*width as usize) + x.rem_euclid(*width) as usize;
                cells.get(index).copied().unwrap_or(0)
            }
        }
    }
}

/// Realize before any destination pixel is touched: an unresolvable pattern
/// depth fails the whole operation instead of painting part of it.
/// # C: O(pattern pixels)
pub(super) fn fill(style: BrushStyle, pattern: Option<&BitmapPattern>, colors: SharedDcColors) -> Result<Fill, GdiError> {
    match style {
        BrushStyle::Solid(color) => Ok(Fill::Uniform(color)),
        BrushStyle::Hollow => Ok(Fill::Uniform(0)),
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
