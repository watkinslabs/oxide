//! Read-only canonical identity snapshots for client ABI publication.
use super::*;

impl GdiManager {
    /// Read selected identity using internal GDI type bits, never public OBJ indices.
    /// # C: O(DCs)
    pub fn selected_object(&self, dc: u32, kind: u32) -> Option<u32> {
        let state = &self.dcs.iter().find(|(id, _)| *id == dc)?.1;
        state.ensure_active().ok()?;
        match kind {
            TYPE_FONT => Some(state.font.unwrap_or(DEFAULT_DC_FONT_HANDLE)),
            TYPE_BRUSH => state.brush.or_else(|| self.stock_object(0).map(|stock| stock.handle)),
            TYPE_PEN => Some(state.pen),
            _ => None,
        }
    }
    /// Existing window DC lookup never allocates or resizes. # C: O(windows)
    pub fn window_dc(&self, hwnd: u32) -> Option<u32> {
        self.window_dcs.iter().find(|(window, _)| *window == hwnd).map(|(_, dc)| *dc)
    }

    /// Object liveness derives only from canonical storage, including retained selections. # C: O(objects)
    pub fn contains_object(&self, handle: u32) -> bool {
        self.stock_description(handle).is_some() || self.dcs.iter().any(|(id, _)| *id == handle)
            || self.fonts.iter().any(|(id, _)| *id == handle) || self.brushes.iter().any(|(id, _)| *id == handle)
            || self.regions.iter().any(|(id, _)| *id == handle) || self.pens.iter().any(|(id, _)| *id == handle)
    }

    /// Owned identity snapshot; no borrowed object escapes publication setup. # C: O(objects)
    pub fn live_handles(&self) -> Vec<u32> {
        (0..20).filter_map(|index| self.stock_object(index).map(|object| object.handle))
            .chain(self.dcs.iter().map(|(id, _)| *id)).chain(self.fonts.iter().map(|(id, _)| *id))
            .chain(self.brushes.iter().map(|(id, _)| *id)).chain(self.regions.iter().map(|(id, _)| *id))
            .chain(self.pens.iter().map(|(id, _)| *id)).collect()
    }
}

#[cfg(test)]
#[path = "tests/projection.rs"]
mod tests;
