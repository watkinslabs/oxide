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


pub(crate) const SW_SHOWNORMAL: u64 = 1;
pub(crate) const SW_SHOWMINIMIZED: u64 = 2;
pub(crate) const SW_SHOWMAXIMIZED: u64 = 3;
pub(crate) const SW_SHOWNOACTIVATE: u64 = 4;
pub(crate) const SW_SHOW: u64 = 5;
pub(crate) const SW_MINIMIZE: u64 = 6;
pub(crate) const SW_SHOWMINNOACTIVE: u64 = 7;
pub(crate) const SW_SHOWNA: u64 = 8;
pub(crate) const SW_RESTORE: u64 = 9;
pub(crate) const SW_SHOWDEFAULT: u64 = 10;
const WS_CHILD: u32 = 0x4000_0000;

/// What one show command projects onto the window stack besides visibility:
/// the reference finishes every show that reaches its positioning step by
/// placing the window at the top of its band and activating it, and suppresses
/// each of those two independently per command and for a child window. A show
/// that projects neither leaves a newly mapped window wherever the display
/// already had it in the stack - under whatever it was meant to appear over.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ShowProjection { pub raise: bool, pub activate: bool }

impl ShowProjection {
    /// # C: O(1)
    pub(crate) fn projects(self) -> bool { self.raise || self.activate }
}

/// Resolve that projection. `None` names the commands the reference answers
/// without reaching its positioning step at all: an unknown command, a show of
/// an already-visible window, and a hide of an already-hidden one.
/// # C: O(1)
pub(crate) fn show_projection(command: u64, style: u32, was_visible: bool) -> Option<ShowProjection> {
    let child = style & WS_CHILD != 0;
    let both = ShowProjection { raise: true, activate: true };
    match command {
        SW_HIDE => was_visible.then_some(ShowProjection { raise: !child, activate: false }),
        // A minimize neither reorders nor activates, whichever window it is.
        SW_MINIMIZE | SW_SHOWMINNOACTIVE | SW_FORCEMINIMIZE | SW_SHOWNOACTIVATE => Some(ShowProjection::default()),
        // The iconic and maximized shows carry no child suppression.
        SW_SHOWMINIMIZED | SW_SHOWMAXIMIZED => Some(both),
        SW_SHOWNA => Some(ShowProjection { raise: !child, activate: false }),
        SW_SHOW => (!was_visible).then_some(ShowProjection { raise: !child, activate: !child }),
        SW_SHOWNORMAL | SW_RESTORE | SW_SHOWDEFAULT =>
            (!was_visible).then_some(ShowProjection { raise: !child, activate: !child }),
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

    use super::{show_projection, ShowProjection, SW_SHOW, SW_SHOWMAXIMIZED, SW_SHOWMINIMIZED,
        SW_SHOWNA, SW_SHOWNOACTIVATE, SW_SHOWNORMAL, SW_MINIMIZE, SW_RESTORE, SW_SHOWMINNOACTIVE};
    const WS_CHILD: u32 = 0x4000_0000;
    const WS_POPUP: u32 = 0x8000_0000;
    const DIALOG: u32 = WS_POPUP | 0x00C0_0000 | 0x0008_0000;

    #[test]
    fn showing_an_owned_dialog_raises_it_and_activates_it() {
        assert_eq!(show_projection(SW_SHOW, DIALOG, false), Some(ShowProjection { raise: true, activate: true }));
        assert_eq!(show_projection(SW_SHOWNORMAL, DIALOG, false), Some(ShowProjection { raise: true, activate: true }));
        assert_eq!(show_projection(SW_RESTORE, DIALOG, false), Some(ShowProjection { raise: true, activate: true }));
        assert!(show_projection(SW_SHOW, DIALOG, false).unwrap().projects());
    }

    #[test]
    fn showing_a_child_control_touches_neither_stack_nor_activation() {
        for command in [SW_SHOW, SW_SHOWNORMAL, SW_SHOWNA, SW_RESTORE] {
            assert_eq!(show_projection(command, WS_CHILD, false), Some(ShowProjection::default()), "command {command}");
        }
        assert!(!show_projection(SW_SHOW, WS_CHILD, false).unwrap().projects());
    }

    #[test]
    fn a_show_without_activation_still_raises_a_top_level_window() {
        assert_eq!(show_projection(SW_SHOWNA, DIALOG, false), Some(ShowProjection { raise: true, activate: false }));
        assert_eq!(show_projection(SW_SHOWNOACTIVATE, DIALOG, false), Some(ShowProjection::default()));
        assert_eq!(show_projection(SW_MINIMIZE, DIALOG, false), Some(ShowProjection::default()));
        assert_eq!(show_projection(SW_SHOWMINNOACTIVE, DIALOG, false), Some(ShowProjection::default()));
    }

    #[test]
    fn the_iconic_and_maximized_shows_carry_no_child_suppression() {
        for command in [SW_SHOWMINIMIZED, SW_SHOWMAXIMIZED] {
            assert_eq!(show_projection(command, WS_CHILD, false), Some(ShowProjection { raise: true, activate: true }));
            assert_eq!(show_projection(command, DIALOG, true), Some(ShowProjection { raise: true, activate: true }));
        }
    }

    #[test]
    fn a_show_that_changes_nothing_projects_nothing_at_all() {
        assert_eq!(show_projection(SW_SHOW, DIALOG, true), None);
        assert_eq!(show_projection(SW_SHOWNORMAL, DIALOG, true), None);
        assert_eq!(show_projection(SW_HIDE, DIALOG, false), None);
        assert_eq!(show_projection(SW_HIDE, DIALOG, true), Some(ShowProjection { raise: true, activate: false }));
        assert_eq!(show_projection(12, DIALOG, false), None);
    }
}
