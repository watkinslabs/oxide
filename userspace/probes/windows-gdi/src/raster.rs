use fontdue::{Font as TrueTypeFont, FontSettings};

const MAX_TEXT_PIXELS: usize = 16 * 1024 * 1024;

#[derive(Debug, Eq, PartialEq)]
pub enum RasterError { InvalidFont, InvalidSize, TooLarge }

pub struct RasterFont { font: TrueTypeFont, size: f32 }

pub struct RasterSurface { pub width: u32, pub height: u32, pub pixels: Vec<u32> }

impl RasterFont {
    /// Load a TrueType/OpenType font from caller-owned bytes. # C: O(font_size)
    pub fn from_bytes(bytes: &[u8], size: f32) -> Result<Self, RasterError> {
        if !size.is_finite() || size <= 0.0 { return Err(RasterError::InvalidSize); }
        let font = TrueTypeFont::from_bytes(bytes, FontSettings { scale: size, ..FontSettings::default() }).map_err(|_| RasterError::InvalidFont)?;
        Ok(Self { font, size })
    }

    /// Rasterize UTF-16 text into an opaque XRGB tile using native font metrics. # C: O(N_text + pixels)
    pub fn rasterize(&self, text: &[u16], foreground: u32, background: u32) -> Result<RasterSurface, RasterError> {
        let mut glyphs = Vec::new();
        let mut width = 0.0f32;
        let mut top = 0i32;
        let mut bottom = self.size.ceil() as i32;
        for decoded in char::decode_utf16(text.iter().copied()) {
            let character = decoded.unwrap_or(char::REPLACEMENT_CHARACTER);
            let (metrics, bitmap) = self.font.rasterize(character, self.size);
            let x = width.round() as i32 + metrics.xmin;
            top = top.min(metrics.ymin);
            bottom = bottom.max(metrics.ymin + metrics.height as i32);
            width += metrics.advance_width;
            glyphs.push((x, metrics.ymin, metrics.width, metrics.height, bitmap));
        }
        let tile_width = width.ceil().max(1.0) as usize;
        let tile_height = (bottom - top).max(1) as usize;
        let Some(pixel_count) = tile_width.checked_mul(tile_height) else { return Err(RasterError::TooLarge); };
        if pixel_count > MAX_TEXT_PIXELS { return Err(RasterError::TooLarge); }
        let mut pixels = vec![background; pixel_count];
        for (x, glyph_top, glyph_width, glyph_height, bitmap) in glyphs {
            let y = glyph_top - top;
            for glyph_y in 0..glyph_height { for glyph_x in 0..glyph_width {
                let alpha = bitmap[glyph_y * glyph_width + glyph_x] as u32;
                if alpha == 0 { continue; }
                let dest_x = x + glyph_x as i32;
                let dest_y = y + glyph_y as i32;
                if dest_x < 0 || dest_y < 0 || dest_x >= tile_width as i32 || dest_y >= tile_height as i32 { continue; }
                pixels[dest_y as usize * tile_width + dest_x as usize] = blend(foreground, background, alpha);
            } }
        }
        Ok(RasterSurface { width: tile_width as u32, height: tile_height as u32, pixels })
    }
}

fn blend(foreground: u32, background: u32, alpha: u32) -> u32 {
    let channel = |shift: u32| ((foreground >> shift & 0xff) * alpha + (background >> shift & 0xff) * (255 - alpha) + 127) / 255;
    channel(16) << 16 | channel(8) << 8 | channel(0)
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
}
