//! Process/window-station user settings shared by Win32 user calls.

pub const DEFAULT_CARET_BLINK_MS: u32 = 500;
/// Interval within which two clicks are one double click, in milliseconds.
pub const DEFAULT_DOUBLE_CLICK_MS: u32 = 500;
/// Dwell before a tracked pointer reports a hover, in milliseconds.
pub const DEFAULT_MOUSE_HOVER_MS: u32 = 400;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct UserSettings { caret_blink_ms: u32, double_click_ms: u32, mouse_hover_ms: u32 }

impl UserSettings {
    pub const fn new() -> Self {
        Self { caret_blink_ms: DEFAULT_CARET_BLINK_MS, double_click_ms: DEFAULT_DOUBLE_CLICK_MS,
            mouse_hover_ms: DEFAULT_MOUSE_HOVER_MS }
    }
    /// # C: O(1)
    pub const fn double_click_ms(&self) -> u32 { self.double_click_ms }
    /// Store the double-click interval and answer the previous one. # C: O(1)
    pub fn set_double_click_ms(&mut self, value: u32) -> u32 { core::mem::replace(&mut self.double_click_ms, value) }
    /// # C: O(1)
    pub const fn mouse_hover_ms(&self) -> u32 { self.mouse_hover_ms }
    /// Store the hover dwell and answer the previous one. # C: O(1)
    pub fn set_mouse_hover_ms(&mut self, value: u32) -> u32 { core::mem::replace(&mut self.mouse_hover_ms, value) }
    pub const fn caret_blink_ms(&self) -> u32 { self.caret_blink_ms }

    /// Store the Win32 UINT value and return the previous value.
    ///
    /// Wine accepts the complete UINT domain here; the ABI type is the
    /// validation boundary and zero is not rewritten into a guessed default.
    pub fn set_caret_blink_ms(&mut self, value: u32) -> u32 {
        let previous = self.caret_blink_ms;
        self.caret_blink_ms = value;
        previous
    }
}

impl Default for UserSettings { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pointer_settings_carry_their_reference_defaults_and_round_trip() {
        let mut settings = UserSettings::new();
        assert_eq!(settings.double_click_ms(), DEFAULT_DOUBLE_CLICK_MS);
        assert_eq!(settings.mouse_hover_ms(), DEFAULT_MOUSE_HOVER_MS);
        assert_eq!(settings.set_double_click_ms(120), DEFAULT_DOUBLE_CLICK_MS);
        assert_eq!(settings.double_click_ms(), 120);
        assert_eq!(settings.set_mouse_hover_ms(0), DEFAULT_MOUSE_HOVER_MS);
        assert_eq!(settings.mouse_hover_ms(), 0);
    }

    #[test]
    fn caret_blink_setting_has_reference_default_and_round_trips_uint() {
        let mut settings = UserSettings::new();
        assert_eq!(settings.caret_blink_ms(), DEFAULT_CARET_BLINK_MS);
        assert_eq!(settings.set_caret_blink_ms(0), DEFAULT_CARET_BLINK_MS);
        assert_eq!(settings.caret_blink_ms(), 0);
        assert_eq!(settings.set_caret_blink_ms(u32::MAX), 0);
        assert_eq!(settings.caret_blink_ms(), u32::MAX);
    }
}
