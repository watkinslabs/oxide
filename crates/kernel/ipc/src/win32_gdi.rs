//! Pure GDI object state used by the native NT GUI layer.

use alloc::vec::Vec;

pub const MM_TEXT: u32 = 1;
const DEFAULT_HEIGHT: i32 = 16;
const DEFAULT_DESCENT: i32 = 4;
const DEFAULT_WIDTH: i32 = 8;
const MAX_SURFACE_PIXELS: usize = 16 * 1024 * 1024;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Font { pub height: i32, pub width: i32, pub weight: i32, pub italic: bool }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TextMetrics { pub height: i32, pub ascent: i32, pub descent: i32, pub average_width: i32, pub max_width: i32, pub character_width: i32 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TextExtent { pub width: i32, pub height: i32 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Rect { pub left: i32, pub top: i32, pub right: i32, pub bottom: i32 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum GdiError { NoSuchObject, InvalidDimensions, InvalidText }

#[derive(Debug, Eq, PartialEq)]
struct DeviceContext { width: i32, height: i32, map_mode: u32, font: Option<u32>, pixels: Vec<u32> }

pub struct GdiManager { next: u32, dcs: Vec<(u32, DeviceContext)>, fonts: Vec<(u32, Font)> }

impl Default for GdiManager { fn default() -> Self { Self::new() } }

impl GdiManager {
    /// Construct an empty process-local GDI object owner. # C: O(1)
    pub fn new() -> Self { Self { next: 1, dcs: Vec::new(), fonts: Vec::new() } }

    /// Create a memory device context with bounded positive dimensions. # C: O(1)
    pub fn create_dc(&mut self, width: i32, height: i32) -> Result<u32, GdiError> {
        if width <= 0 || height <= 0 || (width as usize).checked_mul(height as usize).is_none_or(|pixels| pixels > MAX_SURFACE_PIXELS) { return Err(GdiError::InvalidDimensions); }
        let handle = self.allocate();
        self.dcs.push((handle, DeviceContext { width, height, map_mode: MM_TEXT, font: None, pixels: alloc::vec![0; (width as usize) * (height as usize)] }));
        Ok(handle)
    }

    /// Create a logical font object from its requested metrics. # C: O(1)
    pub fn create_font(&mut self, font: Font) -> Result<u32, GdiError> {
        if font.height == i32::MIN || font.width == i32::MIN { return Err(GdiError::InvalidDimensions); }
        let handle = self.allocate();
        self.fonts.push((handle, font));
        Ok(handle)
    }

    /// Delete a device context or font object. # C: O(N_objects)
    pub fn delete_object(&mut self, handle: u32) -> Result<(), GdiError> {
        if let Some(index) = self.dcs.iter().position(|(candidate, _)| *candidate == handle) {
            self.dcs.remove(index); return Ok(());
        }
        if let Some(index) = self.fonts.iter().position(|(candidate, _)| *candidate == handle) {
            self.fonts.remove(index);
            for (_, dc) in &mut self.dcs { if dc.font == Some(handle) { dc.font = None; } }
            return Ok(());
        }
        Err(GdiError::NoSuchObject)
    }

    /// Select a font into a device context and return the previous font. # C: O(N_objects)
    pub fn select_font(&mut self, dc: u32, font: u32) -> Result<u32, GdiError> {
        if !self.fonts.iter().any(|(candidate, _)| *candidate == font) { return Err(GdiError::NoSuchObject); }
        let Some((_, state)) = self.dcs.iter_mut().find(|(candidate, _)| *candidate == dc) else { return Err(GdiError::NoSuchObject); };
        let previous = state.font.unwrap_or(0); state.font = Some(font); Ok(previous)
    }

    /// Return text metrics for the selected font or the stock font. # C: O(N_objects)
    pub fn text_metrics(&self, dc: u32) -> Result<TextMetrics, GdiError> {
        let font = self.font_for(dc)?;
        let height = metric_height(font);
        let width = metric_width(font, height);
        Ok(TextMetrics { height, ascent: height - DEFAULT_DESCENT, descent: DEFAULT_DESCENT, average_width: width, max_width: width, character_width: width })
    }

    /// Measure UTF-16 code units using the selected logical font. # C: O(N_text)
    pub fn text_extent(&self, dc: u32, count: u32) -> Result<TextExtent, GdiError> {
        if count > i32::MAX as u32 { return Err(GdiError::InvalidText); }
        let font = self.font_for(dc)?;
        let height = metric_height(font);
        let width = metric_width(font, height).checked_mul(count as i32).ok_or(GdiError::InvalidText)?;
        Ok(TextExtent { width, height })
    }

    /// Fill a clipped device-context rectangle with one XRGB color. # C: O(width*height)
    pub fn fill_rect(&mut self, dc: u32, rect: Rect, color: u32) -> Result<(), GdiError> {
        let Some((_, state)) = self.dcs.iter_mut().find(|(candidate, _)| *candidate == dc) else { return Err(GdiError::NoSuchObject); };
        let left = rect.left.max(0).min(state.width) as usize;
        let top = rect.top.max(0).min(state.height) as usize;
        let right = rect.right.max(0).min(state.width) as usize;
        let bottom = rect.bottom.max(0).min(state.height) as usize;
        if right <= left || bottom <= top { return Ok(()); }
        for y in top..bottom { for x in left..right { state.pixels[y * state.width as usize + x] = color; } }
        Ok(())
    }

    /// Copy a row-major XRGB raster into a clipped device-context surface. # C: O(width*height)
    pub fn blit_pixels(&mut self, dc: u32, x: i32, y: i32, width: i32, height: i32, stride: i32, pixels: &[u32]) -> Result<(), GdiError> {
        if width <= 0 || height <= 0 || stride < width || pixels.len() < (height as usize).checked_mul(stride as usize).ok_or(GdiError::InvalidDimensions)? { return Err(GdiError::InvalidDimensions); }
        let Some((_, state)) = self.dcs.iter_mut().find(|(candidate, _)| *candidate == dc) else { return Err(GdiError::NoSuchObject); };
        for source_y in 0..height {
            let dest_y = y.saturating_add(source_y);
            if dest_y < 0 || dest_y >= state.height { continue; }
            for source_x in 0..width {
                let dest_x = x.saturating_add(source_x);
                if dest_x < 0 || dest_x >= state.width { continue; }
                state.pixels[dest_y as usize * state.width as usize + dest_x as usize] = pixels[source_y as usize * stride as usize + source_x as usize];
            }
        }
        Ok(())
    }

    /// Read the rendered row-major XRGB surface for one device context. # C: O(1)
    pub fn pixels(&self, dc: u32) -> Option<&[u32]> { self.dcs.iter().find(|(candidate, _)| *candidate == dc).map(|(_, state)| state.pixels.as_slice()) }

    fn font_for(&self, dc: u32) -> Result<Option<Font>, GdiError> {
        let Some((_, state)) = self.dcs.iter().find(|(candidate, _)| *candidate == dc) else { return Err(GdiError::NoSuchObject); };
        Ok(state.font.and_then(|handle| self.fonts.iter().find(|(candidate, _)| *candidate == handle).map(|(_, font)| *font)))
    }

    fn allocate(&mut self) -> u32 { let handle = self.next; self.next = self.next.saturating_add(1); handle }
}

fn metric_height(font: Option<Font>) -> i32 { font.map(|font| font.height.abs().max(1)).unwrap_or(DEFAULT_HEIGHT) }
fn metric_width(font: Option<Font>, height: i32) -> i32 { font.map(|font| font.width.abs().max(1)).unwrap_or((height / 2).max(DEFAULT_WIDTH)) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dc_font_selection_and_metrics_share_one_owner() {
        let mut gdi = GdiManager::new();
        let dc = gdi.create_dc(800, 600).unwrap();
        let font = gdi.create_font(Font { height: 20, width: 10, weight: 400, italic: false }).unwrap();
        assert_eq!(gdi.select_font(dc, font), Ok(0));
        assert_eq!(gdi.text_metrics(dc).unwrap().height, 20);
        assert_eq!(gdi.text_extent(dc, 4), Ok(TextExtent { width: 40, height: 20 }));
    }

    #[test]
    fn deleting_font_unselects_all_contexts() {
        let mut gdi = GdiManager::new();
        let dc = gdi.create_dc(10, 10).unwrap();
        let font = gdi.create_font(Font { height: 12, width: 0, weight: 400, italic: false }).unwrap();
        gdi.select_font(dc, font).unwrap();
        gdi.delete_object(font).unwrap();
        assert_eq!(gdi.text_metrics(dc).unwrap().height, DEFAULT_HEIGHT);
    }

    #[test]
    fn invalid_dimensions_and_handles_are_rejected() {
        let mut gdi = GdiManager::new();
        assert_eq!(gdi.create_dc(0, 10), Err(GdiError::InvalidDimensions));
        assert_eq!(gdi.delete_object(99), Err(GdiError::NoSuchObject));
    }

    #[test]
    fn fill_rect_clips_to_the_native_surface() {
        let mut gdi = GdiManager::new();
        let dc = gdi.create_dc(4, 3).unwrap();
        gdi.fill_rect(dc, Rect { left: -1, top: 1, right: 3, bottom: 4 }, 0x0011_2233).unwrap();
        let px = gdi.pixels(dc).unwrap();
        assert_eq!(px[0], 0);
        assert_eq!(px[4], 0x0011_2233);
        assert_eq!(px[10], 0x0011_2233);
        assert_eq!(px[11], 0);
    }

    #[test]
    fn blit_pixels_clips_source_raster_without_aliasing_surface_state() {
        let mut gdi = GdiManager::new();
        let dc = gdi.create_dc(3, 2).unwrap();
        let source = [0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc];
        gdi.blit_pixels(dc, -1, 0, 3, 2, 3, &source).unwrap();
        assert_eq!(gdi.pixels(dc).unwrap(), &[0x22, 0x33, 0, 0xbb, 0xcc, 0]);
    }
}
