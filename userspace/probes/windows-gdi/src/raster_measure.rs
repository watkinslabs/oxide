use super::{RasterFont, RasterError};

pub struct FontMeasurement { pub width: i32, pub height: i32, pub fit: u32, pub cumulative: Vec<i32> }

impl RasterFont {
    /// Measure selected glyph IDs without Unicode decoding or a second font realization.
    pub fn measure_glyphs(&self, glyphs: &[u16], max_extent: i32) -> Result<FontMeasurement, RasterError> {
        let mut cumulative = Vec::with_capacity(glyphs.len());
        let mut advance = 0f32;
        for glyph in glyphs {
            if *glyph >= self.font.glyph_count() { return Err(RasterError::InvalidFont); }
            advance += self.font.metrics_indexed(*glyph, self.size).advance_width * self.width_scale;
            if !advance.is_finite() || advance < 0.0 || advance.ceil() >= i32::MAX as f32 { return Err(RasterError::TooLarge); }
            cumulative.push(advance.ceil() as i32);
        }
        let fit = cumulative.iter().take_while(|p| **p as u32 <= max_extent as u32).count() as u32;
        let height = if glyphs.is_empty() { 0 } else { self.cell_height()? };
        Ok(FontMeasurement { width: cumulative.last().copied().unwrap_or(0), height, fit, cumulative })
    }
    /// Measure exactly the unkerned glyph advances consumed by this renderer.
    pub fn measure_utf16(&self, text: &[u16], max_extent: i32) -> Result<FontMeasurement, RasterError> {
        let mut cumulative = Vec::with_capacity(text.len());
        let mut advance = 0.0f32;
        for decoded in char::decode_utf16(text.iter().copied()) {
            let character = decoded.unwrap_or(char::REPLACEMENT_CHARACTER);
            advance += self.font.metrics(character, self.size).advance_width * self.width_scale;
            if !advance.is_finite() || advance < 0.0 || advance.ceil() >= i32::MAX as f32 { return Err(RasterError::TooLarge); }
            for _ in 0..character.len_utf16() { cumulative.push(advance.ceil() as i32); }
        }
        let fit = cumulative.iter().take_while(|position| **position as u32 <= max_extent as u32).count() as u32;
        let height = if text.is_empty() { 0 } else { self.cell_height()? };
        Ok(FontMeasurement { width: cumulative.last().copied().unwrap_or(0), height, fit, cumulative })
    }

    fn cell_height(&self) -> Result<i32, RasterError> {
        let line = self.font.horizontal_line_metrics(self.size).ok_or(RasterError::InvalidFont)?;
        Ok(line.ascent.ceil() as i32 + (-line.descent).ceil() as i32)
    }

    /// Serialize the complete TEXTMETRICW record from this selected static font.
    pub fn text_metrics_w(&self, weight: i32, italic: u32) -> Result<[u8; 60], RasterError> {
        let line = self.font.horizontal_line_metrics(self.size).ok_or(RasterError::InvalidFont)?;
        let ascent = line.ascent.ceil() as i32;
        let descent = (-line.descent).ceil() as i32;
        let height = ascent + descent;
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let average = (alphabet.chars().map(|c| self.font.metrics(c, self.size).advance_width * self.width_scale).sum::<f32>() / 52.0).round() as i32;
        let maximum = (self.font.chars().keys().map(|c| self.font.metrics(*c, self.size).advance_width).fold(0.0f32, f32::max) * self.width_scale).ceil() as i32;
        let first = self.font.chars().keys().filter(|c| **c as u32 <= u16::MAX as u32).map(|c| *c as u16).min().unwrap_or(0);
        let last = self.font.chars().keys().filter(|c| **c as u32 <= u16::MAX as u32).map(|c| *c as u16).max().unwrap_or(0);
        let replacement = if self.font.chars().contains_key(&char::REPLACEMENT_CHARACTER) { 0xfffd } else { b'?' as u16 };
        let mut bytes = [0u8; 60];
        for (index, value) in [height, ascent, descent, (height - self.size.ceil() as i32).max(0),
            line.line_gap.ceil().max(0.0) as i32, average, maximum, if weight >= 600 { 700 } else { 400 },
            0, 96, 96].into_iter().enumerate() { bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes()); }
        for (index, value) in [first, last, replacement, b' ' as u16].into_iter().enumerate() {
            bytes[44 + index * 2..46 + index * 2].copy_from_slice(&value.to_le_bytes());
        }
        bytes[52] = u8::from(italic != 0);
        // Static substitution is fixed-pitch TrueType, vector, modern family; ANSI charset.
        bytes[55] = 0x36;
        Ok(bytes)
    }
}
