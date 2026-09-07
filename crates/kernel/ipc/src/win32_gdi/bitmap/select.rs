//! Binding one bitmap to a memory device context; 31fk§4.
use super::{GdiError, GdiManager};

/// Depth a device-dependent bitmap must match to be selectable, beyond
/// monochrome: the device's own depth. A display-compatible context also
/// accepts thirty-two bits because it emulates every other depth.
const DISPLAY_DEPTH: u32 = super::super::SURFACE_BITS_PER_PIXEL;

impl GdiManager {
    /// The bitmap one device context renders into, if it selected one. # C: O(DCs)
    pub fn dc_bitmap(&self, dc: u32) -> Option<u32> {
        self.dcs.iter().find(|(id, _)| *id == dc).and_then(|(_, state)| state.bitmap)
    }

    /// Only a memory device context selects a bitmap; every other context
    /// answers nothing. Selecting the bitmap a context already holds changes
    /// nothing and reports it. A bitmap already selected in another context is
    /// refused, as is a device-dependent bitmap whose depth the device neither
    /// matches nor emulates. Success resizes the context to the bitmap.
    /// # C: O(DCs + bitmaps)
    pub fn select_bitmap(&mut self, dc: u32, bitmap: u32) -> Result<u32, GdiError> {
        let state = &self.dcs.iter().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        if !state.memory { return Err(GdiError::NoSuchObject); }
        state.ensure_active()?;
        let previous = state.bitmap;
        if previous == Some(bitmap) { return Ok(bitmap); }
        let selected = self.bitmap(bitmap)?;
        let (width, height, bpp, is_dib) = (selected.width, selected.height, selected.bpp, selected.dib.is_some());
        if self.dcs.iter().any(|(id, other)| *id != dc && other.bitmap == Some(bitmap)) { return Err(GdiError::NoSuchObject); }
        if !is_dib && bpp != 1 && bpp != DISPLAY_DEPTH { return Err(GdiError::InvalidDimensions); }
        let state = &mut self.dcs.iter_mut().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        state.bitmap = Some(bitmap);
        state.width = width;
        state.height = height;
        state.clip = None;
        state.paint_clip = None;
        self.collect_deleted_bitmaps();
        Ok(previous.unwrap_or(0))
    }
}

#[cfg(test)]
#[path = "../tests/bitmap_select.rs"]
mod tests;
