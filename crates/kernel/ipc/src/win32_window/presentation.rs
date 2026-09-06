//! Backend creation acknowledgment belongs to the canonical HWND lifetime.
use super::*;

impl WindowManager {
    /// # C: O(windows)
    pub fn window_styles(&self, id: WindowId) -> Option<(u32, u32)> { self.get(id).map(|record| (record.style, record.ex_style)) }

    /// Styles outlive pending creation and remain owned by the HWND record.
    /// # C: O(windows)
    pub fn set_window_styles(&mut self, id: WindowId, style: u32, ex_style: u32) -> Result<(u32, u32), WindowError> {
        let (_, owned) = self.windows.iter_mut().find(|(window, _)| *window == id).ok_or(WindowError::NoSuchWindow)?;
        let record = &mut owned.record;
        let previous = (record.style, record.ex_style);
        record.style = style;
        record.ex_style = ex_style;
        owned.sync_scrollbar_visibility(style);
        Ok(previous)
    }

    /// # C: O(windows)
    pub fn presentation_ready(&self, id: WindowId) -> Option<bool> { self.get(id).map(|record| record.presentation_ready) }

    /// Set true only after backend Create ACK; clear before rollback/destruction.
    /// # C: O(windows)
    pub fn set_presentation_ready(&mut self, id: WindowId, ready: bool) -> Result<(), WindowError> {
        let record = self.windows.iter_mut().find(|(window, _)| *window == id).ok_or(WindowError::NoSuchWindow)?;
        record.1.presentation_ready = ready; Ok(())
    }
}

#[cfg(test)]
#[path = "tests/presentation.rs"]
mod tests;
