//! Two marks the reference keeps on the window itself: the dialog's own state
//! pointer, and whether the window is an MDI client.
//!
//! Both are set by the dialog and MDI managers through the window entry and
//! read back by the one-window queries; neither is derivable from the styles,
//! which is why the window carries them.

use super::{WindowError, WindowId, WindowManager};

impl WindowManager {
    /// The dialog state pointer one window carries, zero for a window that is
    /// not a dialog. The kernel never dereferences it. # C: O(N_windows)
    pub fn dialog_info(&self, id: WindowId) -> Option<u64> { self.get(id).map(|record| record.dlg_info) }

    /// Hand one window its dialog state pointer, answering the one it held.
    /// # C: O(N_windows)
    pub fn set_dialog_info(&mut self, id: WindowId, info: u64) -> Result<u64, WindowError> {
        let (_, record) = self.windows.iter_mut().find(|(window, _)| *window == id).ok_or(WindowError::NoSuchWindow)?;
        let previous = record.dlg_info;
        record.dlg_info = info;
        Ok(previous)
    }

    /// Whether one window is an MDI client, which is what makes its client
    /// info readable. # C: O(N_windows)
    pub fn is_mdi_client(&self, id: WindowId) -> Option<bool> { self.get(id).map(|record| record.mdi_client) }

    /// Mark one window an MDI client. The mark is never taken back: the
    /// reference sets the bit and clears none. # C: O(N_windows)
    pub fn mark_mdi_client(&mut self, id: WindowId) -> Result<(), WindowError> {
        let (_, record) = self.windows.iter_mut().find(|(window, _)| *window == id).ok_or(WindowError::NoSuchWindow)?;
        record.mdi_client = true;
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/dialog.rs"]
mod tests;
