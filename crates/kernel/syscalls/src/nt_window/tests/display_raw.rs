//! Display decisions: monitor DPI by awareness, point admission, mode matching.
use super::*;
use ipc::win32_window::WindowRect;

#[test]
fn an_unaware_caller_always_sees_the_default_screen_dpi() {
    assert_eq!(monitor_dpi(0, 192, 144), USER_DEFAULT_SCREEN_DPI);
}

#[test]
fn a_system_aware_caller_always_sees_the_system_dpi() {
    assert_eq!(monitor_dpi(1, 192, 144), 192);
}

#[test]
fn a_per_monitor_caller_sees_the_monitors_own_dpi() {
    assert_eq!(monitor_dpi(2, 192, 144), 144);
    assert_eq!(monitor_dpi(3, 192, 144), 144);
}

#[test]
fn a_point_conversion_applies_only_inside_the_window_it_names() {
    let rect = WindowRect { left: 10, top: 20, right: 110, bottom: 120 };
    assert!(point_inside((10, 20), rect));
    assert!(point_inside((110, 120), rect));
    assert!(point_inside((60, 70), rect));
    assert!(!point_inside((9, 20), rect));
    assert!(!point_inside((10, 19), rect));
    assert!(!point_inside((111, 60), rect));
    assert!(!point_inside((60, 121), rect));
}

#[test]
fn a_mode_request_naming_no_field_accepts_the_current_mode() {
    assert!(mode_matches((0, 0, 0, 0), (1920, 1080, 32, 60)));
}

#[test]
fn every_named_field_must_match() {
    assert!(mode_matches((1920, 0, 0, 60), (1920, 1080, 32, 60)));
    assert!(!mode_matches((1024, 0, 0, 0), (1920, 1080, 32, 60)));
    assert!(!mode_matches((1920, 1080, 32, 75), (1920, 1080, 32, 60)));
    assert!(mode_matches((1920, 1080, 32, 60), (1920, 1080, 32, 60)));
}

#[test]
fn a_test_or_no_reset_request_never_applies_the_mode() {
    assert!(applies_mode(0));
    assert!(applies_mode(CDS_UPDATEREGISTRY));
    assert!(!applies_mode(CDS_TEST));
    assert!(!applies_mode(CDS_NORESET));
    assert!(!applies_mode(CDS_TEST | CDS_UPDATEREGISTRY));
}
