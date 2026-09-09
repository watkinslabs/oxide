//! Scrollbar control state belongs to its HWND, separate from standard bars.
use super::{ScrollState, ScrollError, ScrollInfo, ScrollOutcome, SB_CTL, ESB_DISABLE_BOTH};
use crate::win32_window::{WindowId, WindowManager};
use crate::win32_window::styles::WS_DISABLED;
use crate::win32_window::window_fnid::make_fnid;

/// Builtin procedure-array index for a scrollbar control.
pub const PROC_SCROLLBAR: u16 = 0;

impl WindowManager {
    /// WM_CREATE initializes control storage and reserves its builtin extra area.
    /// # C: O(N_windows)
    pub fn initialize_scroll_control(&mut self, window: WindowId) -> Result<(), ScrollError> {
        self.set_window_fnid(window, make_fnid(PROC_SCROLLBAR)).map_err(|_| ScrollError::InvalidWindow)?;
        let (_, owned) = self.windows.iter_mut().find(|(id, _)| *id == window).ok_or(ScrollError::InvalidWindow)?;
        let mut state = ScrollState::new();
        if owned.record.style & WS_DISABLED != 0 { state.flags = ESB_DISABLE_BOTH; }
        owned.scroll_control = Some(state);
        Ok(())
    }

    /// Controls without a completed creation have no scroll state.
    /// # C: O(N_windows)
    pub fn scroll_control_state(&self, window: WindowId) -> Result<ScrollState, ScrollError> {
        let (_, owned) = self.windows.iter().find(|(id, _)| *id == window).ok_or(ScrollError::InvalidWindow)?;
        owned.scroll_control.ok_or(ScrollError::InvalidBar)
    }

    fn scroll_control_mut(&mut self, window: WindowId) -> Result<&mut ScrollState, ScrollError> {
        let (_, owned) = self.windows.iter_mut().find(|(id, _)| *id == window).ok_or(ScrollError::InvalidWindow)?;
        owned.scroll_control.as_mut().ok_or(ScrollError::InvalidBar)
    }

    /// The control procedure consumes the state result; it must not send itself
    /// another SBM_SETSCROLLINFO. # C: O(N_windows)
    pub fn set_scroll_control_info(&mut self, window: WindowId, info: ScrollInfo, redraw: bool) -> Result<ScrollOutcome, ScrollError> {
        let mut outcome = self.scroll_control_mut(window)?.apply_for_bar(SB_CTL, info, redraw)?;
        outcome.action.control_message = false;
        Ok(outcome)
    }

    /// SBM_SETRANGE stores endpoints without the SCROLLINFO normalization step.
    /// # C: O(N_windows)
    pub fn set_scroll_control_range(&mut self, window: WindowId, min: i32, max: i32) -> Result<(), ScrollError> {
        let state = self.scroll_control_mut(window)?;
        state.min = min; state.max = max;
        Ok(())
    }

    /// WM_ENABLE and arrow APIs update the same control-owned flags.
    /// # C: O(N_windows)
    pub fn set_scroll_control_flags(&mut self, window: WindowId, flags: u32) -> Result<bool, ScrollError> {
        let state = self.scroll_control_mut(window)?;
        let changed = state.flags != flags; state.flags = flags;
        Ok(changed)
    }
}

#[cfg(test)]
#[path = "tests/control.rs"]
mod tests;
