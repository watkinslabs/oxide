//! Pointer-width child identifiers on the canonical HWND; never menu handles.
use super::{WindowError, WindowId, WindowManager};

use super::styles::{WS_CHILD, WS_POPUP};
#[cfg(test)] use super::extra::GWLP_ID;

/// A window whose `GWLP_ID` slot is a control identifier: a child that is not
/// also a popup. Every other window keeps a menu handle there. # C: O(1)
pub const fn is_effective_child(style: u32) -> bool { style & (WS_CHILD | WS_POPUP) == WS_CHILD }

/// Read the shared identifier slot as a menu handle, which it is for every
/// window the style does not make an effective child. # C: O(1)
pub const fn menu_of(style: u32, id_menu: u64) -> Option<u32> {
    if is_effective_child(style) { return None; }
    match id_menu { 0 => None, handle if handle <= u32::MAX as u64 => Some(handle as u32), _ => None }
}

impl WindowManager {
    /// Replace an effective child's identifier without touching its menu association.
    /// # C: O(N_windows)
    pub fn set_control_id(&mut self, window: WindowId, value: u64) -> Result<u64, WindowError> {
        let record = &mut self.windows.iter_mut().find(|(id, _)| *id == window)
            .ok_or(WindowError::NoSuchWindow)?.1;
        if !is_effective_child(record.style) { return Err(WindowError::InvalidParent); }
        let previous = record.id_menu;
        record.id_menu = value;
        Ok(previous)
    }

    /// Query an effective child's full pointer-width identifier, including zero.
    /// # C: O(N_windows)
    pub fn control_id(&self, window: WindowId) -> Option<u64> {
        let record = self.get(window)?;
        is_effective_child(record.style).then_some(record.id_menu)
    }
}

#[cfg(test)]
#[path = "tests/control.rs"]
mod tests;
