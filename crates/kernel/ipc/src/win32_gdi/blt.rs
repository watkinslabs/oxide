//! Source-dependent raster operations between device contexts; 31fk§4.
//! Module manifest: `rop.rs` owns the ternary raster truth table and the
//! stretch sampling; `pixel.rs` owns single-pixel read, write and flood fill;
//! `blend.rs` owns per-pixel alpha, transparency and gradient interpolation;
//! `mask.rs` owns the masked and parallelogram copies built on them.
use super::{GdiError, GdiManager, Rect, SharedDcColors};
#[path = "blt/rop.rs"]
mod rop;
#[path = "blt/pixel.rs"]
mod pixel;
#[path = "blt/blend.rs"]
mod blend;
#[path = "blt/mask.rs"]
mod mask;
pub use rop::{rop3, rop_uses_source, signed_span, StretchMode, BLACKONWHITE, WHITEONBLACK, COLORONCOLOR, HALFTONE};
pub use blend::{BlendFunction, TriVertex, GradientMode, AC_SRC_OVER, AC_SRC_ALPHA,
    GRADIENT_FILL_RECT_H, GRADIENT_FILL_RECT_V, GRADIENT_FILL_TRIANGLE};
pub use pixel::{FLOODFILLBORDER, FLOODFILLSURFACE};

/// The reference names raster operations by their whole thirty-two bit code;
/// the ternary truth table is its third byte.
pub const SRCCOPY: u32 = 0x00cc_0020;
pub const SRCAND: u32 = 0x0088_00c6;
pub const SRCPAINT: u32 = 0x00ee_0086;
/// A bit that asks the operation not to mirror a mirrored layout.
pub const NOMIRRORBITMAP: u32 = 0x8000_0000;

/// One source rectangle sampled for a destination rectangle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BltCoords { pub x: i32, pub y: i32, pub width: i32, pub height: i32 }

impl GdiManager {
    /// Copy with a full ternary raster operation. A code that does not read
    /// its source is the pattern-only operation instead. Source pixels are
    /// snapshotted before any destination write, so a context blitted onto
    /// itself reads its own pre-operation state.
    /// # C: O(DCs + source pixels + clipped pixels)
    pub fn stretch_blt(&mut self, dst: u32, dst_rect: BltCoords, src: u32, src_rect: BltCoords,
        code: u32, colors: SharedDcColors, mode: StretchMode) -> Result<(), GdiError> {
        let code = code & !NOMIRRORBITMAP;
        if !rop_uses_source(code) {
            return self.pat_blt_shared_colors(dst, dst_rect.x, dst_rect.y, dst_rect.width, dst_rect.height, code, colors);
        }
        if dst_rect.width == 0 || dst_rect.height == 0 || src_rect.width == 0 || src_rect.height == 0 {
            return Err(GdiError::InvalidDimensions);
        }
        let table = (code >> 16) as u8;
        let fill = self.realized_brush_fill(dst, colors)?;
        let (source_width, source_height, source) = self.dc_pixel_snapshot(src).ok_or(GdiError::NoSuchObject)?;
        let sample = rop::Sampler { pixels: &source, width: source_width, height: source_height, mode };
        let mut target = self.raster_dc(dst)?;
        let clip = target.bounds();
        let (left, right) = rop::signed_span(dst_rect.x, dst_rect.width, clip.left, clip.right);
        let (top, bottom) = rop::signed_span(dst_rect.y, dst_rect.height, clip.top, clip.bottom);
        for y in top..bottom { for x in left..right {
            let Some(source_pixel) = sample.at(dst_rect, src_rect, x, y) else { continue; };
            let Some(pattern) = fill.color(x, y) else { continue; };
            target.update(x, y, |old| rop3(table, pattern, source_pixel, old));
        } }
        Ok(())
    }

    /// Equal source and destination extents; the reference routes it through
    /// the stretching operation unchanged. # C: O(DCs + copied pixels)
    pub fn bit_blt(&mut self, dst: u32, x: i32, y: i32, width: i32, height: i32, src: u32, src_x: i32, src_y: i32,
        code: u32, colors: SharedDcColors) -> Result<(), GdiError> {
        self.stretch_blt(dst, BltCoords { x, y, width, height }, src,
            BltCoords { x: src_x, y: src_y, width, height }, code, colors, COLORONCOLOR)
    }

    /// Mirrored extents are refused before anything is read. The transparent
    /// colour is compared against the stretched source, and matching pixels
    /// leave the destination untouched. # C: O(DCs + destination pixels)
    pub fn transparent_blt(&mut self, dst: u32, dst_rect: BltCoords, src: u32, src_rect: BltCoords,
        transparent: u32) -> Result<(), GdiError> {
        if dst_rect.width < 0 || dst_rect.height < 0 || src_rect.width < 0 || src_rect.height < 0 {
            return Err(GdiError::InvalidDimensions);
        }
        if dst_rect.width == 0 || dst_rect.height == 0 || src_rect.width == 0 || src_rect.height == 0 { return Ok(()); }
        let (source_width, source_height, source) = self.dc_pixel_snapshot(src).ok_or(GdiError::NoSuchObject)?;
        let sample = rop::Sampler { pixels: &source, width: source_width, height: source_height, mode: COLORONCOLOR };
        let mut target = self.raster_dc(dst)?;
        let clip = target.bounds();
        let (left, right) = rop::signed_span(dst_rect.x, dst_rect.width, clip.left, clip.right);
        let (top, bottom) = rop::signed_span(dst_rect.y, dst_rect.height, clip.top, clip.bottom);
        for y in top..bottom { for x in left..right {
            let Some(pixel) = sample.at(dst_rect, src_rect, x, y) else { continue; };
            if pixel == transparent { continue; }
            target.update(x, y, |_| pixel);
        } }
        Ok(())
    }

    /// Per-pixel alpha over a stretched source. Negative extents, a source
    /// larger than its context and an overlapping self-blit are all refused
    /// before any pixel moves. # C: O(DCs + destination pixels)
    pub fn alpha_blend(&mut self, dst: u32, dst_rect: BltCoords, src: u32, src_rect: BltCoords,
        blend: BlendFunction) -> Result<(), GdiError> {
        if src_rect.x < 0 || src_rect.y < 0 || src_rect.width < 0 || src_rect.height < 0
            || dst_rect.width < 0 || dst_rect.height < 0 { return Err(GdiError::InvalidDimensions); }
        let (source_width, source_height, source) = self.dc_pixel_snapshot(src).ok_or(GdiError::NoSuchObject)?;
        if src_rect.width > source_width - src_rect.x || src_rect.height > source_height - src_rect.y {
            return Err(GdiError::InvalidDimensions);
        }
        if src == dst && src_rect.x + src_rect.width > dst_rect.x && src_rect.x < dst_rect.x + dst_rect.width
            && src_rect.y + src_rect.height > dst_rect.y && src_rect.y < dst_rect.y + dst_rect.height {
            return Err(GdiError::InvalidDimensions);
        }
        if dst_rect.width == 0 || dst_rect.height == 0 || src_rect.width == 0 || src_rect.height == 0 { return Ok(()); }
        let sample = rop::Sampler { pixels: &source, width: source_width, height: source_height, mode: COLORONCOLOR };
        let mut target = self.raster_dc(dst)?;
        let clip = target.bounds();
        let (left, right) = rop::signed_span(dst_rect.x, dst_rect.width, clip.left, clip.right);
        let (top, bottom) = rop::signed_span(dst_rect.y, dst_rect.height, clip.top, clip.bottom);
        for y in top..bottom { for x in left..right {
            let Some(pixel) = sample.at(dst_rect, src_rect, x, y) else { continue; };
            target.update(x, y, |old| blend.apply(pixel, old));
        } }
        Ok(())
    }

    /// Interpolate colour across every named rectangle or triangle. Every
    /// index must name a supplied vertex, and the mode must be one the
    /// reference names. # C: O(DCs + covered pixels)
    pub fn gradient_fill(&mut self, dc: u32, vertices: &[TriVertex], indexes: &[u32], mode: GradientMode) -> Result<(), GdiError> {
        let shapes = blend::gradient_shapes(vertices, indexes, mode).ok_or(GdiError::InvalidDimensions)?;
        let mut target = self.raster_dc(dc)?;
        let clip = target.bounds();
        for shape in &shapes {
            let bounds = shape.bounds();
            for y in bounds.top.max(clip.top)..bounds.bottom.min(clip.bottom) {
                for x in bounds.left.max(clip.left)..bounds.right.min(clip.right) {
                    let Some(color) = shape.color_at(x, y) else { continue; };
                    target.update(x, y, |_| color);
                }
            }
        }
        Ok(())
    }

    /// Realize the destination's selected brush once per operation. # C: O(brushes + pattern pixels)
    fn realized_brush_fill(&self, dc: u32, colors: SharedDcColors) -> Result<super::brush::Fill, GdiError> {
        let handle = self.selected_brush_handle(dc)?;
        let style = self.brush_style(handle, colors.brush)?;
        super::brush::fill(style, self.brush_pattern(handle), colors)
    }
}

/// Bounding rectangle helpers shared by the gradient shapes. # C: O(1)
pub(super) fn bounding(points: &[(i32, i32)]) -> Rect {
    let mut rect = Rect { left: i32::MAX, top: i32::MAX, right: i32::MIN, bottom: i32::MIN };
    for (x, y) in points {
        rect.left = rect.left.min(*x); rect.top = rect.top.min(*y);
        rect.right = rect.right.max(*x); rect.bottom = rect.bottom.max(*y);
    }
    rect
}

#[cfg(test)]
#[path = "tests/blt.rs"]
mod tests;
