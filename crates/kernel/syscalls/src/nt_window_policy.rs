//! Hosted Win32 window-transition policy shared by the native GUI shim.

pub(crate) const WM_SHOWWINDOW: u32 = 0x0018;

/// Return the WM_SHOWWINDOW wParam for one real visibility transition. # C: O(1)
pub(crate) fn visibility_transition_message(previous: bool, visible: bool) -> Option<u64> {
    (previous != visible).then_some(visible as u64)
}

#[cfg(test)]
mod tests {
    use super::{visibility_transition_message, WM_SHOWWINDOW};

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
}
