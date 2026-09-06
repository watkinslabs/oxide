//! Hosted Win32 window-transition policy shared by the native GUI shim.

pub(crate) const WM_SHOWWINDOW: u32 = 0x0018;
pub(crate) const SW_HIDE: u64 = 0;
pub(crate) const SW_FORCEMINIMIZE: u64 = 11;

pub(crate) const CALL_ONE_PARAM_GET_SYSTEM_METRICS: u64 = 9;

/// Return the WM_SHOWWINDOW wParam for one real visibility transition. # C: O(1)
pub(crate) fn visibility_transition_message(previous: bool, visible: bool) -> Option<u64> {
    (previous != visible).then_some(visible as u64)
}

/// Resolve a ShowWindow command, rejecting commands outside the Win32 set. # C: O(1)
pub(crate) fn show_command_visibility(command: u64) -> Option<bool> {
    match command {
        SW_HIDE => Some(false),
        1..=SW_FORCEMINIMIZE => Some(true),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{show_command_visibility, visibility_transition_message,
        SW_FORCEMINIMIZE, SW_HIDE, WM_SHOWWINDOW};
    const SW_SHOWDEFAULT: u64 = 10;

    #[test]
    fn show_window_notifies_when_visibility_changes() {
        assert_eq!(visibility_transition_message(false, true), Some(1));
        assert_eq!(visibility_transition_message(true, false), Some(0));
        assert_eq!(WM_SHOWWINDOW, 0x0018);
    }

    #[test]
    fn show_window_does_not_notify_for_an_idempotent_request() {
        assert_eq!(visibility_transition_message(false, false), None);
        assert_eq!(visibility_transition_message(true, true), None);
    }

    #[test]
    fn show_window_accepts_only_the_reference_command_range() {
        assert_eq!(show_command_visibility(SW_HIDE), Some(false));
        assert_eq!(show_command_visibility(1), Some(true));
        assert_eq!(show_command_visibility(SW_SHOWDEFAULT), Some(true));
        assert_eq!(show_command_visibility(SW_FORCEMINIMIZE), Some(true));
    }

    #[test]
    fn show_window_unknown_command_is_a_noop() {
        assert_eq!(show_command_visibility(12), None);
        assert_eq!(show_command_visibility(u64::MAX), None);
    }

}
