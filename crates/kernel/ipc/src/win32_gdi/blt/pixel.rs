//! Single-pixel access and flood fill; 31fk§4.
use alloc::vec::Vec;
use super::super::{GdiError, GdiManager, CLR_INVALID};

/// Flood fill stops at a border colour, or spreads across one surface colour.
pub const FLOODFILLBORDER: u32 = 0;
pub const FLOODFILLSURFACE: u32 = 1;
const RGB_MASK: u32 = 0x00ff_ffff;

impl GdiManager {
    /// Colour of one clipped device pixel; a position the clip excludes has
    /// no colour to report. # C: O(DCs + region rectangles)
    pub fn get_pixel(&mut self, dc: u32, x: i32, y: i32) -> Result<u32, GdiError> {
        let target = self.raster_dc(dc)?;
        if !target.covers(x, y) { return Ok(CLR_INVALID); }
        Ok(target.read(x, y).map_or(CLR_INVALID, |color| color & RGB_MASK))
    }

    /// Store one clipped device pixel, answering the colour actually stored.
    /// A position the clip excludes stores nothing. # C: O(DCs + region rectangles)
    pub fn set_pixel(&mut self, dc: u32, x: i32, y: i32, color: u32) -> Result<u32, GdiError> {
        let color = color & RGB_MASK;
        let mut target = self.raster_dc(dc)?;
        if !target.update(x, y, |_| color) { return Ok(CLR_INVALID); }
        Ok(target.read(x, y).map_or(CLR_INVALID, |stored| stored & RGB_MASK))
    }

    /// Spread the selected brush colour from one seed. A border fill stops at
    /// the named colour; a surface fill covers exactly the connected run of it.
    /// A seed outside the clip fills nothing. # C: O(clipped pixels)
    pub fn ext_flood_fill(&mut self, dc: u32, x: i32, y: i32, color: u32, fill_type: u32,
        colors: super::super::SharedDcColors) -> Result<(), GdiError> {
        if fill_type != FLOODFILLBORDER && fill_type != FLOODFILLSURFACE { return Err(GdiError::InvalidDimensions); }
        let color = color & RGB_MASK;
        let fill = self.realized_brush_fill(dc, colors)?;
        let mut target = self.raster_dc(dc)?;
        let clip = target.bounds();
        let Some(seed) = target.read(x, y) else { return Err(GdiError::InvalidDimensions); };
        let admits = |candidate: u32| if fill_type == FLOODFILLBORDER { candidate != color } else { candidate == color };
        if !admits(seed & RGB_MASK) { return Err(GdiError::InvalidDimensions); }
        let (span, rows) = ((clip.right - clip.left).max(0) as usize, (clip.bottom - clip.top).max(0) as usize);
        let cells = span.checked_mul(rows).ok_or(GdiError::InvalidDimensions)?;
        let mut visited = Vec::new();
        visited.try_reserve_exact(cells).map_err(|_| GdiError::HandleLimit)?;
        visited.resize(cells, false);
        let mut pending = Vec::new();
        pending.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
        pending.push((x, y));
        while let Some((x, y)) = pending.pop() {
            if x < clip.left || x >= clip.right || y < clip.top || y >= clip.bottom { continue; }
            let slot = (y - clip.top) as usize * span + (x - clip.left) as usize;
            if visited[slot] { continue; }
            visited[slot] = true;
            let Some(current) = target.read(x, y) else { continue; };
            if !admits(current & RGB_MASK) { continue; }
            let Some(paint) = fill.color(x, y) else { continue; };
            target.update(x, y, |_| paint);
            pending.try_reserve(4).map_err(|_| GdiError::HandleLimit)?;
            for step in [(1, 0), (-1, 0), (0, 1), (0, -1)] { pending.push((x + step.0, y + step.1)); }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/blt_pixel.rs"]
mod tests;
