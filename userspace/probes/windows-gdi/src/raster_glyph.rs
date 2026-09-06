use super::{RasterFont, RasterError};
impl RasterFont {
    /// Convert selected resource design units using the same em and logical-width scales.
    pub fn scale_design_units(&self, value: i32, horizontal: bool) -> i32 {
        (value as f32 * self.size / self.font.units_per_em() * if horizontal { self.width_scale } else { 1.0 }).round() as i32
    }
    /// Map WCHAR units independently; preserve missing glyph marker and real default glyph.
    pub fn glyph_indices(&self, text: &[u16], default: u16, mark_missing: bool) -> Vec<u16> {
        let default = if mark_missing { u16::MAX } else if default == 0 { 0 }
            else { char::from_u32(default as u32).map(|c| self.font.lookup_glyph_index(c)).unwrap_or(0) };
        text.iter().map(|unit| {
            let glyph = char::from_u32(*unit as u32).map(|c| self.font.lookup_glyph_index(c)).unwrap_or(0);
            if glyph == 0 { default } else { glyph }
        }).collect()
    }
    /// Integer ABC derives from the same scaled bitmap bounds and glyph advance as drawing.
    pub fn glyph_abc(&self, glyph: u16) -> Result<[i32; 3], RasterError> {
        if glyph >= self.font.glyph_count() { return Err(RasterError::InvalidFont); }
        let metrics = self.font.metrics_indexed(glyph, self.size);
        let a = (metrics.xmin as f32 * self.width_scale).round() as i32;
        let b = (metrics.width as f32 * self.width_scale).ceil() as i32;
        let advance = (metrics.advance_width * self.width_scale).round() as i32;
        Ok([a, b, advance - a - b])
    }
}
