use fontdue::{Font as TrueTypeFont, FontSettings};
use crate::{Gdi, GdiError, Rect};
#[path = "raster_measure.rs"]
mod measure;
#[path = "raster_glyph.rs"]
mod glyph;
#[path = "raster_positioned.rs"]
mod positioned;
pub use measure::FontMeasurement;

const MAX_TEXT_PIXELS: usize = 16 * 1024 * 1024;
pub const ETO_OPAQUE: u32 = 0x0002;
pub const ETO_CLIPPED: u32 = 0x0004;

#[derive(Debug, Eq, PartialEq)]
pub enum RasterError { InvalidFont, InvalidSize, TooLarge }

#[derive(Debug)]
pub enum TextOutputError { Raster(RasterError), Gdi(GdiError) }

pub struct RasterFont { font: TrueTypeFont, size: f32, width_scale: f32 }

pub struct RasterSurface { pub width: u32, pub height: u32, pub pixels: Vec<u32> }

impl RasterFont {
    /// Load a TrueType/OpenType font from caller-owned bytes. # C: O(font_size)
    pub fn from_bytes(bytes: &[u8], size: f32) -> Result<Self, RasterError> {
        if !size.is_finite() || size <= 0.0 { return Err(RasterError::InvalidSize); }
        let font = TrueTypeFont::from_bytes(bytes, FontSettings { scale: size, ..FontSettings::default() }).map_err(|_| RasterError::InvalidFont)?;
        Ok(Self { font, size, width_scale: 1.0 })
    }

    /// Apply logical average width to glyph geometry and natural advances, not caller lpDx.
    pub fn with_logical_width(mut self, width: i32) -> Result<Self, RasterError> {
        let width = width.checked_abs().ok_or(RasterError::InvalidSize)?;
        if width > syscall::nt_native_gdi::MAX_WIDTH { return Err(RasterError::InvalidSize); }
        if width == 0 { self.width_scale = 1.0; return Ok(self); }
        let average = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".chars()
            .map(|c| self.font.metrics(c, self.size).advance_width as f64).sum::<f64>() / 52.0;
        if !average.is_finite() || average <= 0.0 { return Err(RasterError::InvalidFont); }
        self.width_scale = (f64::from(width) / average) as f32;
        Ok(self)
    }

    /// Rasterize UTF-16 text into an opaque XRGB tile using native font metrics. # C: O(N_text + pixels)
    pub fn rasterize(&self, text: &[u16], foreground: u32, background: u32) -> Result<RasterSurface, RasterError> {
        self.rasterize_with_advances(text, None, foreground, background)
    }

    /// Rasterize text with optional per-code-unit advances supplied by `lpDx`. # C: O(N_text + pixels)
    pub fn rasterize_with_advances(&self, text: &[u16], advances: Option<&[i32]>, foreground: u32, background: u32) -> Result<RasterSurface, RasterError> {
        self.rasterize_background(text, advances, foreground, Some(background))
    }

    /// Preserve glyph coverage as non-premultiplied ARGB for destination blending. # C: O(N_text + pixels)
    pub fn rasterize_alpha(&self, text: &[u16], advances: Option<&[i32]>, foreground: u32) -> Result<RasterSurface, RasterError> {
        self.rasterize_background(text, advances, foreground, None)
    }

    fn rasterize_background(&self, text: &[u16], advances: Option<&[i32]>, foreground: u32, background: Option<u32>) -> Result<RasterSurface, RasterError> {
        self.rasterize_positioned(text, advances, 0, foreground, background).map(|(_, _, raster)| raster)
    }

    /// Implement the userspace portion of `ExtTextOutW`, including opaque and clipped output. # C: O(N_text + pixels) plus kernel service
    pub fn ext_text_out(&self, gdi: &Gdi, dc: u64, x: i32, y: i32, flags: u32, rect: Option<Rect>, text: &[u16], advances: Option<&[i32]>, foreground: u32, background: u32) -> Result<(), TextOutputError> {
        if flags & (ETO_OPAQUE | ETO_CLIPPED) != 0 && rect.is_none() { return Err(TextOutputError::Raster(RasterError::InvalidSize)); }
        let (left, top, surface) = self.rasterize_positioned(text, advances, flags, foreground, Some(background)).map_err(TextOutputError::Raster)?;
        let x = x.checked_add(left).ok_or(TextOutputError::Raster(RasterError::TooLarge))?;
        let y = y.checked_add(top).ok_or(TextOutputError::Raster(RasterError::TooLarge))?;
        if flags & ETO_OPAQUE != 0 {
            let Some(rect) = rect else { return Err(TextOutputError::Raster(RasterError::InvalidSize)); };
            gdi.fill_rect(dc, rect, background).map_err(TextOutputError::Gdi)?;
        }
        if text.is_empty() { return Ok(()); }
        if flags & ETO_CLIPPED != 0 {
            let Some(rect) = rect else { return Err(TextOutputError::Raster(RasterError::InvalidSize)); };
            gdi.draw_raster_clipped(dc, x, y, &surface, rect).map_err(TextOutputError::Gdi)
        } else {
            gdi.draw_raster(dc, x, y, &surface).map_err(TextOutputError::Gdi)
        }
    }
}

fn blend(foreground: u32, background: u32, alpha: u32) -> u32 {
    let channel = |shift: u32| ((foreground >> shift & 0xff) * alpha + (background >> shift & 0xff) * (255 - alpha) + 127) / 255;
    channel(16) << 16 | channel(8) << 8 | channel(0)
}

fn advance_for_utf16_span(advances: &[i32], start: usize, units: usize, stride: usize, axis: usize) -> Option<i64> {
    if axis >= stride || stride == 0 { return None; }
    let range = advances.get(start.checked_mul(stride)?..start.checked_add(units)?.checked_mul(stride)?)?;
    Some(range.iter().skip(axis).step_by(stride).map(|v| i64::from(*v)).sum())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_font_and_scale_without_ffi_or_host_dependencies() {
        assert!(matches!(RasterFont::from_bytes(&[], 12.0), Err(RasterError::InvalidFont)));
        assert!(matches!(RasterFont::from_bytes(&[], 0.0), Err(RasterError::InvalidSize)));
    }

    #[test]
    fn blends_xrgb_channels_without_alpha_in_surface_contract() {
        assert_eq!(blend(0x00ff_0000, 0x0000_0000, 128), 0x0080_0000);
        assert_eq!(blend(0x0012_3456, 0x00ab_cdef, 0), 0x00ab_cdef);
        assert_eq!(blend(0x0012_3456, 0x00ab_cdef, 255), 0x0012_3456);
    }

    #[test]
    fn ext_text_out_consumes_advances_per_utf16_code_unit() {
        let text = [0xd83d, 0xde00, b'X' as u16];
        let mut start = 0;
        let mut total = 0;
        for decoded in char::decode_utf16(text.iter().copied()) {
            let character = decoded.unwrap_or(char::REPLACEMENT_CHARACTER);
            let units = character.len_utf16();
            total += advance_for_utf16_span(&[10, 20, 30], start, units, 1, 0).unwrap();
            start += units;
        }
        assert_eq!(start, text.len());
        assert_eq!(total, 60);
    }

    #[test]
    fn ext_text_out_rejects_advances_shorter_than_utf16_count() {
        assert_eq!(advance_for_utf16_span(&[10], 0, 2, 1, 0), None);
        assert_eq!(advance_for_utf16_span(&[10, 20], 1, 2, 1, 0), None);
    }
}
