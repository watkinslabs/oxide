//! Pure GDI object state used by the native NT GUI layer.

use alloc::vec::Vec;

pub const MM_TEXT: u32 = 1;
const DEFAULT_HEIGHT: i32 = 16;
const DEFAULT_DESCENT: i32 = 4;
const DEFAULT_WIDTH: i32 = 8;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Font { pub height: i32, pub width: i32, pub weight: i32, pub italic: bool }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TextMetrics { pub height: i32, pub ascent: i32, pub descent: i32, pub average_width: i32, pub max_width: i32, pub character_width: i32 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TextExtent { pub width: i32, pub height: i32 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum GdiError { NoSuchObject, InvalidDimensions, InvalidText }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct DeviceContext { width: i32, height: i32, map_mode: u32, font: Option<u32> }

pub struct GdiManager { next: u32, dcs: Vec<(u32, DeviceContext)>, fonts: Vec<(u32, Font)> }

impl Default for GdiManager { fn default() -> Self { Self::new() } }

impl GdiManager {
    /// Construct an empty process-local GDI object owner. # C: O(1)
    pub fn new() -> Self { Self { next: 1, dcs: Vec::new(), fonts: Vec::new() } }

    /// Create a memory device context with bounded positive dimensions. # C: O(1)
    pub fn create_dc(&mut self, width: i32, height: i32) -> Result<u32, GdiError> {
        if width <= 0 || height <= 0 { return Err(GdiError::InvalidDimensions); }
        let handle = self.allocate();
        self.dcs.push((handle, DeviceContext { width, height, map_mode: MM_TEXT, font: None }));
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
}
