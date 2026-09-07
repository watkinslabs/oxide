//! Scrollbar show/enable/info admission.
use super::*;

#[test]
fn a_show_request_moves_only_the_bars_it_names() {
    assert_eq!(show_targets(SB_HORZ, true), Some((true, false)));
    assert_eq!(show_targets(SB_VERT, true), Some((false, true)));
    assert_eq!(show_targets(SB_BOTH, true), Some((true, true)));
    assert_eq!(show_targets(SB_HORZ, false), Some((false, false)));
    assert_eq!(show_targets(SB_VERT, false), Some((false, false)));
}

#[test]
fn a_scrollbar_control_is_not_a_standard_bar_to_show() {
    assert_eq!(show_targets(SB_CTL, true), None);
    assert_eq!(show_targets(9, true), None);
}

#[test]
fn a_show_request_names_the_bars_it_leaves_alone() {
    assert_eq!(show_touches(SB_HORZ), (true, false));
    assert_eq!(show_touches(SB_VERT), (false, true));
    assert_eq!(show_touches(SB_BOTH), (true, true));
}

#[test]
fn the_enable_request_keeps_only_the_arrow_bits() {
    assert_eq!(enable_flags(0), 0);
    assert_eq!(enable_flags(ESB_DISABLE_BOTH), ESB_DISABLE_BOTH);
    assert_eq!(enable_flags(u32::MAX), ESB_DISABLE_BOTH);
    assert_eq!(enable_flags(0x1000_0001), 1);
}

#[test]
fn each_accessibility_object_id_names_its_bar() {
    assert_eq!(info_bar(OBJID_CLIENT), Some(SB_CTL));
    assert_eq!(info_bar(OBJID_HSCROLL), Some(SB_HORZ));
    assert_eq!(info_bar(OBJID_VSCROLL), Some(SB_VERT));
    assert_eq!(info_bar(0), None);
    assert_eq!(info_bar(-1), None);
    assert!(defers_to_control(OBJID_CLIENT));
    assert!(!defers_to_control(OBJID_VSCROLL));
}

#[test]
fn only_a_request_that_changes_nothing_reports_no_change() {
    assert!(enable_unchanged(SB_VERT, false, true));
    assert!(!enable_unchanged(SB_VERT, true, false));
    assert!(enable_unchanged(SB_BOTH, true, true));
    assert!(!enable_unchanged(SB_BOTH, true, false));
    assert!(!enable_unchanged(SB_BOTH, false, true));
    assert!(!enable_unchanged(SB_CTL, true, true));
}

#[test]
fn a_both_request_finishes_on_the_horizontal_bar() {
    assert_eq!(enable_target(SB_BOTH), SB_HORZ);
    assert_eq!(enable_target(SB_VERT), SB_VERT);
    assert_eq!(enable_target(SB_CTL), SB_CTL);
}

#[test]
fn a_control_takes_its_windows_enabled_state_only_from_a_whole_bar_request() {
    assert_eq!(control_window_enabled(SB_CTL, ESB_DISABLE_BOTH), Some(false));
    assert_eq!(control_window_enabled(SB_CTL, 0), Some(true));
    assert_eq!(control_window_enabled(SB_CTL, ESB_DISABLE_LTUP), None);
    assert_eq!(control_window_enabled(SB_VERT, 0), None);
}
