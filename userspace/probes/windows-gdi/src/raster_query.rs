use super::{RasterFont, RasterError};

/// One rasterized glyph: whole-pixel placement, size, advance and coverage.
pub struct GlyphRaster {
    pub left: i32, pub bottom: i32, pub width: usize, pub height: usize,
    pub advance: i32, pub coverage: Vec<u8>,
}

impl RasterFont {
    /// Supported character codes of the selected resource, ascending. # C: O(chars log chars)
    pub fn character_codes(&self) -> Vec<u32> {
        let mut codes: Vec<u32> = self.font.chars().keys().map(|c| *c as u32).collect();
        codes.sort_unstable();
        codes
    }

    /// Glyph identifier for one character code, zero when unsupported. # C: O(1)
    pub fn glyph_for(&self, code: u32) -> u16 {
        char::from_u32(code).map(|c| self.font.lookup_glyph_index(c)).unwrap_or(0)
    }

    /// Number of glyph identifiers the selected resource defines. # C: O(1)
    pub fn glyph_count(&self) -> u16 { self.font.glyph_count() }

    /// Design units per em of the selected resource. # C: O(1)
    pub fn design_units_per_em(&self) -> f32 { self.font.units_per_em() }

    /// Raster em size this realization was built at. # C: O(1)
    pub fn pixel_size(&self) -> f32 { self.size }

    /// Horizontal scale applied to advances by a logical average width. # C: O(1)
    pub fn width_scale(&self) -> f32 { self.width_scale }

    /// Rasterize one glyph at the realized size. # C: O(pixels)
    pub fn glyph_raster(&self, glyph: u16) -> Result<GlyphRaster, RasterError> {
        if glyph >= self.font.glyph_count() { return Err(RasterError::InvalidFont); }
        let (metrics, coverage) = self.font.rasterize_indexed(glyph, self.size);
        if coverage.len() != metrics.width * metrics.height { return Err(RasterError::InvalidFont); }
        let advance = (metrics.advance_width * self.width_scale).round();
        if !advance.is_finite() || advance.abs() >= i32::MAX as f32 { return Err(RasterError::TooLarge); }
        Ok(GlyphRaster { left: metrics.xmin, bottom: metrics.ymin, width: metrics.width,
            height: metrics.height, advance: advance as i32, coverage })
    }
}
