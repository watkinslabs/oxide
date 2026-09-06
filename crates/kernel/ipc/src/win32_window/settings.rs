//! Process/window-station user settings shared by Win32 user calls.

pub const DEFAULT_CARET_BLINK_MS: u32 = 500;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct UserSettings { caret_blink_ms: u32 }

impl UserSettings {
    pub const fn new() -> Self { Self { caret_blink_ms: DEFAULT_CARET_BLINK_MS } }
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
    fn caret_blink_setting_has_reference_default_and_round_trips_uint() {
        let mut settings = UserSettings::new();
        assert_eq!(settings.caret_blink_ms(), DEFAULT_CARET_BLINK_MS);
        assert_eq!(settings.set_caret_blink_ms(0), DEFAULT_CARET_BLINK_MS);
        assert_eq!(settings.caret_blink_ms(), 0);
        assert_eq!(settings.set_caret_blink_ms(u32::MAX), 0);
        assert_eq!(settings.caret_blink_ms(), u32::MAX);
    }
}
