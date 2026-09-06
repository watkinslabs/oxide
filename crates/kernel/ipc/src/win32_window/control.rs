//! Pointer-width child identifiers on the canonical HWND; never menu handles.
use super::{WindowError, WindowId, WindowManager};

const WS_CHILD: u32 = 0x4000_0000;
const WS_POPUP: u32 = 0x8000_0000;

impl WindowManager {
    /// Replace an effective child's identifier without touching its menu association.
    /// # C: O(N_windows)
    pub fn set_control_id(&mut self, window: WindowId, value: u64) -> Result<u64, WindowError> {
        let record = &mut self.windows.iter_mut().find(|(id, _)| *id == window)
            .ok_or(WindowError::NoSuchWindow)?.1;
        if record.style & (WS_CHILD | WS_POPUP) != WS_CHILD { return Err(WindowError::InvalidParent); }
        let previous = record.id_menu;
        record.id_menu = value;
        Ok(previous)
    }

    /// Query an effective child's full pointer-width identifier, including zero.
    /// # C: O(N_windows)
    pub fn control_id(&self, window: WindowId) -> Option<u64> {
        let record = self.get(window)?;
        (record.style & (WS_CHILD | WS_POPUP) == WS_CHILD).then_some(record.id_menu)
    }
}

#[cfg(test)]
#[path = "tests/control.rs"]
mod tests;
