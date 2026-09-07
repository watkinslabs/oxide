//! Style-bit edits and the two calls whose whole contract is one such edit.
use super::*;

impl WindowManager {
    /// Set and clear style bits in one step, answering the previous style.
    /// The set wins over the clear where a bit appears in both.
    /// # C: O(N_windows)
    pub fn set_style_bits(&mut self, id: WindowId, set: u32, clear: u32) -> Result<u32, WindowError> {
        let entry = self.windows.iter_mut().find(|(window, _)| *window == id).ok_or(WindowError::NoSuchWindow)?;
        let old = entry.1.record.style;
        entry.1.record.style = (old & !clear) | set;
        entry.1.record.visible = entry.1.record.style & WS_VISIBLE != 0;
        Ok(old)
    }

    /// Set and clear extended-style bits, answering the previous value.
    /// # C: O(N_windows)
    pub fn set_ex_style_bits(&mut self, id: WindowId, set: u32, clear: u32) -> Result<u32, WindowError> {
        let entry = self.windows.iter_mut().find(|(window, _)| *window == id).ok_or(WindowError::NoSuchWindow)?;
        let old = entry.1.record.ex_style;
        entry.1.record.ex_style = (old & !clear) | set;
        Ok(old)
    }

    /// AlterWindowStyle: apply `style` through `mask`, restricted to the bits
    /// this call is allowed to reach. Answers whether the window exists, which
    /// is what the call reports. # C: O(N_windows)
    pub fn alter_style(&mut self, id: WindowId, mask: u32, style: u32) -> Result<bool, WindowError> {
        let mask = mask & (WS_TABSTOP | WS_VSCROLL | WS_HSCROLL | ALTERABLE_LOW_STYLE);
        self.set_style_bits(id, style & mask, mask & !style)?;
        Ok(true)
    }

    /// EnableWindow: toggle WS_DISABLED and report what the transition owes.
    /// # C: O(N_windows)
    pub fn enable_window(&mut self, id: WindowId, enable: bool) -> Result<EnableOutcome, WindowError> {
        let old = if enable { self.set_style_bits(id, 0, WS_DISABLED)? } else { self.set_style_bits(id, WS_DISABLED, 0)? };
        let previously_disabled = old & WS_DISABLED != 0;
        let changed = previously_disabled == enable;
        let clear_focus = changed && !enable && self.focused() == Some(id);
        if clear_focus { self.set_focus(self.get(id).map_or(0, |record| record.owner_tid), None)?; }
        Ok(EnableOutcome { previously_disabled, changed, clear_focus })
    }

    /// Whether a window accepts input. # C: O(N_windows)
    pub fn is_enabled(&self, id: WindowId) -> bool {
        self.get(id).is_some_and(|record| record.style & WS_DISABLED == 0)
    }
}

/// Low style bits AlterWindowStyle may reach beyond the three named ones.
const ALTERABLE_LOW_STYLE: u32 = 0x0000_023f;
