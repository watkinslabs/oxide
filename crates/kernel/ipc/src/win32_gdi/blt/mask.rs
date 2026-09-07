//! Masked and parallelogram blits; 31fk§4.
use super::super::{GdiError, GdiManager, SharedDcColors};
use super::{BltCoords, COLORONCOLOR, rop, rop3};

/// The determinant below which a parallelogram is degenerate. The reference
/// compares the absolute determinant against one hundred-thousandth; these
/// coordinates are whole device units, so the only degenerate case is zero.
const DEGENERATE_DETERMINANT: i64 = 0;

impl GdiManager {
    /// Combine two raster operations through a monochrome mask: a set mask bit
    /// takes the foreground code's third byte, a clear one the fourth. No mask
    /// leaves the foreground code alone over the whole rectangle.
    /// # C: O(DCs + source pixels + destination pixels)
    pub fn mask_blt(&mut self, dst: u32, x: i32, y: i32, width: i32, height: i32, src: u32, src_x: i32, src_y: i32,
        mask: Option<u32>, mask_x: i32, mask_y: i32, code: u32, colors: SharedDcColors) -> Result<(), GdiError> {
        let Some(mask) = mask else {
            return self.bit_blt(dst, x, y, width, height, src, src_x, src_y, code, colors);
        };
        if width <= 0 || height <= 0 { return Err(GdiError::InvalidDimensions); }
        let (foreground, background) = ((code >> 16) as u8, (code >> 24) as u8);
        let pattern = self.bitmap_pattern(mask)?;
        let fill = self.realized_brush_fill(dst, colors)?;
        let (source_width, source_height, source) = self.dc_pixel_snapshot(src).ok_or(GdiError::NoSuchObject)?;
        let sample = rop::Sampler { pixels: &source, width: source_width, height: source_height, mode: COLORONCOLOR };
        let (dst_rect, src_rect) = (BltCoords { x, y, width, height }, BltCoords { x: src_x, y: src_y, width, height });
        let mut target = self.raster_dc(dst)?;
        let clip = target.bounds();
        for row in y.max(clip.top)..(y + height).min(clip.bottom) {
            for column in x.max(clip.left)..(x + width).min(clip.right) {
                let source_pixel = sample.at(dst_rect, src_rect, column, row).unwrap_or(0);
                let Some(brush) = fill.color(column, row) else { continue; };
                // A mask cell outside the mask bitmap selects the background
                // code, which is what an unset monochrome bit does.
                // A monochrome pattern resolves index zero to the first colour
                // given; a set mask bit is index one and selects the foreground.
                let set = pattern.pixel(mask_x + column - x, mask_y + row - y, 0, 1) == Some(1);
                let table = if set { foreground } else { background };
                target.update(column, row, |old| rop3(table, brush, source_pixel, old));
            }
        }
        Ok(())
    }

    /// Copy a source rectangle onto a parallelogram named by its upper-left,
    /// upper-right and lower-left corners. A degenerate parallelogram is
    /// refused before the destination context is touched.
    /// # C: O(DCs + source pixels + destination pixels)
    pub fn plg_blt(&mut self, dst: u32, points: [(i32, i32); 3], src: u32, src_x: i32, src_y: i32,
        width: i32, height: i32, mask: Option<u32>, mask_x: i32, mask_y: i32, colors: SharedDcColors) -> Result<(), GdiError> {
        if determinant(src_x, src_y, width, height) == DEGENERATE_DETERMINANT { return Err(GdiError::InvalidDimensions); }
        let (upper_left, upper_right, lower_left) = (points[0], points[1], points[2]);
        // An axis-aligned parallelogram is a plain masked copy into it.
        if upper_left.1 != upper_right.1 || upper_left.0 != lower_left.0 { return Err(GdiError::InvalidDimensions); }
        let (target_width, target_height) = (upper_right.0 - upper_left.0, lower_left.1 - upper_left.1);
        if target_width != width || target_height != height { return Err(GdiError::InvalidDimensions); }
        self.mask_blt(dst, upper_left.0, upper_left.1, width, height, src, src_x, src_y, mask, mask_x, mask_y,
            super::SRCCOPY, colors)
    }
}

/// Twice the area of the source triangle the transform is derived from. # C: O(1)
fn determinant(x: i32, y: i32, width: i32, height: i32) -> i64 {
    let (x, y, width, height) = (i64::from(x), i64::from(y), i64::from(width), i64::from(height));
    let (right, bottom) = (x + width, y + height);
    right * (bottom - y) - x * (y - y) - x * (bottom - y)
}

#[cfg(test)]
#[path = "../tests/blt_mask.rs"]
mod tests;
