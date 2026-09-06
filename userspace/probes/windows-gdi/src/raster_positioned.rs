use super::{RasterFont, RasterError, RasterSurface, MAX_TEXT_PIXELS, blend};
use syscall::nt_native_gdi as abi;

impl RasterFont {
    /// Rasterize caller glyph IDs or UTF-16 with signed paired placement, retaining tile origin.
    pub fn rasterize_positioned(&self, text: &[u16], advances: Option<&[i32]>, flags: u32,
        foreground: u32, background: Option<u32>) -> Result<(i32, i32, RasterSurface), RasterError> {
        let paired = flags & abi::PDY != 0;
        let stride = if paired { 2 } else { 1 };
        if flags & !(abi::OPAQUE | abi::CLIPPED | abi::GLYPH_INDEX | abi::PDY | abi::IGNORE_LANGUAGE) != 0
            || text.len() > abi::MAX_UNITS as usize || advances.is_some_and(|a| a.len() != text.len() * stride) { return Err(RasterError::InvalidSize); }
        let items: Vec<(u16, usize)> = if flags & abi::GLYPH_INDEX != 0 {
            text.iter().map(|g| (*g, 1)).collect()
        } else {
            char::decode_utf16(text.iter().copied()).map(|c| {
                let c = c.unwrap_or(char::REPLACEMENT_CHARACTER);
                (self.font.lookup_glyph_index(c), c.len_utf16())
            }).collect()
        };
        if items.iter().any(|(g, _)| *g >= self.font.glyph_count()) { return Err(RasterError::InvalidFont); }
        let line = self.font.horizontal_line_metrics(self.size).ok_or(RasterError::InvalidFont)?;
        let ascent = line.ascent.ceil() as i64;
        let mut bounds = [0i64, 0, 1, ascent + (-line.descent).ceil() as i64];
        let (mut pen_x, mut pen_y, mut unit) = (0f64, 0i64, 0usize);
        let mut glyphs = Vec::with_capacity(items.len());
        for (index, units) in items {
            let m = self.font.metrics_indexed(index, self.size);
            let width = (m.width as f32 * self.width_scale).ceil() as usize;
            let x = pen_x.round() as i64 + (m.xmin as f32 * self.width_scale).round() as i64;
            let y = pen_y + ascent - m.ymin as i64 - m.height as i64;
            if m.width != 0 && m.height != 0 {
                bounds[0] = bounds[0].min(x); bounds[1] = bounds[1].min(y);
                bounds[2] = bounds[2].max(x + width as i64); bounds[3] = bounds[3].max(y + m.height as i64);
            }
            if let Some(a) = advances {
                pen_x += super::advance_for_utf16_span(a, unit, units, stride, 0).ok_or(RasterError::InvalidSize)? as f64;
                if paired { pen_y += super::advance_for_utf16_span(a, unit, units, stride, 1).ok_or(RasterError::InvalidSize)?; }
            } else { pen_x += (m.advance_width * self.width_scale) as f64; }
            unit += units;
            bounds[0] = bounds[0].min(pen_x.floor() as i64); bounds[2] = bounds[2].max(pen_x.ceil() as i64);
            glyphs.push((x, y, width, m, index));
        }
        let width = usize::try_from(bounds[2] - bounds[0]).map_err(|_| RasterError::TooLarge)?;
        let height = usize::try_from(bounds[3] - bounds[1]).map_err(|_| RasterError::TooLarge)?;
        let pixels = width.checked_mul(height).filter(|n| *n <= MAX_TEXT_PIXELS).ok_or(RasterError::TooLarge)?;
        let mut pixels = vec![background.unwrap_or(0); pixels];
        for (x, y, scaled_width, m, index) in glyphs {
            if m.width == 0 || m.height == 0 { continue; }
            let (_, bitmap) = self.font.rasterize_indexed(index, self.size);
            for row in 0..m.height { for col in 0..scaled_width {
                let source = (((col as f32 + 0.5) / self.width_scale) as usize).min(m.width - 1);
                let alpha = bitmap[row * m.width + source] as u32;
                if alpha == 0 { continue; }
                let dest = &mut pixels[(y - bounds[1] + row as i64) as usize * width + (x - bounds[0] + col as i64) as usize];
                *dest = match background { Some(_) => blend(foreground, *dest, alpha),
                    None => (alpha + ((*dest >> 24) * (255 - alpha) + 127) / 255) << 24 | foreground & 0xffffff };
            } }
        }
        let x = i32::try_from(bounds[0]).map_err(|_| RasterError::TooLarge)?;
        let y = i32::try_from(bounds[1]).map_err(|_| RasterError::TooLarge)?;
        Ok((x, y, RasterSurface { width: width as u32, height: height as u32, pixels }))
    }
}
