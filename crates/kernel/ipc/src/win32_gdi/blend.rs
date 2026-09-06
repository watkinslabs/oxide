//! Source-over glyph coverage into the canonical XRGB DC surface.
use super::*;

impl GdiManager {
    /// Source is contiguous non-premultiplied ARGB; destination remains XRGB.
    /// All extent validation precedes writes. # C: O(DCs + source pixels)
    pub fn blend_pixels(&mut self, dc: u32, x: i32, y: i32, width: u32, height: u32, pixels: &[u32]) -> Result<(), GdiError> {
        let count = (width as usize).checked_mul(height as usize)
            .filter(|count| *count > 0 && *count <= MAX_SURFACE_PIXELS).ok_or(GdiError::InvalidDimensions)?;
        if pixels.len() != count { return Err(GdiError::InvalidDimensions); }
        let mut target = self.raster_dc(dc)?;
        for row in 0..height as usize {
            let dy = i64::from(y) + row as i64;
            let Ok(dy) = i32::try_from(dy) else { continue; };
            for column in 0..width as usize {
                let dx = i64::from(x) + column as i64;
                let Ok(dx) = i32::try_from(dx) else { continue; };
                target.update(dx, dy, |old| source_over(pixels[row * width as usize + column], old));
            }
        }
        Ok(())
    }
}

fn source_over(source: u32, destination: u32) -> u32 {
    let alpha = source >> 24;
    let mut color = 0;
    for shift in [0, 8, 16] {
        let channel = (((source >> shift) & 255) * alpha
            + ((destination >> shift) & 255) * (255 - alpha) + 127) / 255;
        color |= channel << shift;
    }
    color
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_preserves_background_and_blends_rgb_without_premultiplication() {
        let mut gdi = GdiManager::new();
        let dc = gdi.create_dc(3, 1).unwrap();
        gdi.fill_rect(dc, Rect { left: 0, top: 0, right: 3, bottom: 1 }, 0x0000ff).unwrap();
        gdi.blend_pixels(dc, 0, 0, 3, 1, &[0x00ff0000, 0x80ff0000, 0xffff0000]).unwrap();
        assert_eq!(gdi.pixels(dc).unwrap(), &[0x0000ff, 0x80007f, 0xff0000]);
    }

    #[test]
    fn clipping_and_bad_uploads_do_not_touch_unowned_pixels() {
        let mut gdi = GdiManager::new();
        let dc = gdi.create_dc(2, 1).unwrap();
        gdi.blend_pixels(dc, -1, 0, 2, 1, &[0xffff0000, 0xff00ff00]).unwrap();
        assert_eq!(gdi.pixels(dc).unwrap(), &[0x00ff00, 0]);
        assert!(gdi.blend_pixels(dc, 0, 0, 2, 1, &[0]).is_err());
        assert!(gdi.blend_pixels(dc, 0, 0, u32::MAX, u32::MAX, &[]).is_err());
        assert_eq!(gdi.pixels(dc).unwrap(), &[0x00ff00, 0]);
    }
}
