//! The save/restore stack: one level per SaveDC, unwound by RestoreDC.
use super::{DcAttr, GdiError, GdiManager, TextAttributes};
use crate::win32_window::PaintRegion;

/// Everything one saved level restores. The visible region is deliberately not
/// part of it: a saved level never changes which pixels a context can reach.
#[derive(Clone, Debug, PartialEq)]
pub struct SavedDc {
    pub attr: DcAttr,
    pub text: TextAttributes,
    pub font: Option<u32>,
    pub brush: Option<u32>,
    pub pen: u32,
    pub dc_brush_color: u32,
    pub dc_pen_color: u32,
    pub clip: Option<PaintRegion>,
    pub meta_clip: Option<PaintRegion>,
}

impl GdiManager {
    /// Push one level and report its one-based depth; zero reports failure.
    /// # C: O(DCs)
    pub fn save_dc(&mut self, dc: u32) -> Result<u32, GdiError> {
        let index = self.dcs.iter().position(|(handle, _)| *handle == dc).ok_or(GdiError::NoSuchObject)?;
        self.dcs[index].1.ensure_active()?;
        let state = &self.dcs[index].1;
        let level = SavedDc { attr: state.attr, text: state.text, font: state.font, brush: state.brush,
            pen: state.pen, dc_brush_color: state.dc_brush_color, dc_pen_color: state.dc_pen_color, clip: state.clip.clone(), meta_clip: state.meta_clip.clone() };
        let state = &mut self.dcs[index].1;
        state.saved.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
        state.saved.push(level);
        state.attr.save_level = state.saved.len() as u32;
        Ok(state.attr.save_level)
    }

    /// Restore a saved level, discarding it and every level above it. A
    /// negative level counts back from the current depth; zero, or a magnitude
    /// past the current depth, is refused. # C: O(DCs + discarded levels)
    pub fn restore_dc(&mut self, dc: u32, level: i32) -> Result<(), GdiError> {
        let index = self.dcs.iter().position(|(handle, _)| *handle == dc).ok_or(GdiError::NoSuchObject)?;
        self.dcs[index].1.ensure_active()?;
        let depth = self.dcs[index].1.attr.save_level as i32;
        if level == 0 || level.saturating_abs() > depth { return Err(GdiError::InvalidDimensions); }
        let level = if level < 0 { depth + level + 1 } else { level };
        let state = &mut self.dcs[index].1;
        let restored = state.saved.drain(level as usize - 1..).next().ok_or(GdiError::NoSuchObject)?;
        // The visible rectangle belongs to the surface, so a saved level never
        // moves it; the pixel format likewise outlives the level that saw it.
        let vis_rect = state.attr.vis_rect;
        let pixel_format = state.attr.pixel_format;
        let kind = state.attr.kind;
        state.attr = DcAttr { vis_rect, pixel_format, kind, save_level: level as u32 - 1, ..restored.attr };
        state.text = restored.text;
        state.font = restored.font;
        state.brush = restored.brush;
        state.pen = restored.pen;
        state.dc_brush_color = restored.dc_brush_color;
        state.dc_pen_color = restored.dc_pen_color;
        state.clip = restored.clip;
        state.meta_clip = restored.meta_clip;
        state.attr.update_xforms();
        self.collect_deleted_pens();
        Ok(())
    }

    /// Drop every saved level, as a device-context reset does. # C: O(levels)
    pub fn clear_saved_dc(&mut self, dc: u32) -> Result<(), GdiError> {
        let (_, state) = self.dcs.iter_mut().find(|(handle, _)| *handle == dc).ok_or(GdiError::NoSuchObject)?;
        state.saved.clear();
        state.attr.save_level = 0;
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/save.rs"]
mod tests;
