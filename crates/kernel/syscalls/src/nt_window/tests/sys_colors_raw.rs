//! System-colour index admission.
use super::*;

#[test]
fn a_negative_or_out_of_range_index_names_no_role() {
    assert_eq!(role(-1), None);
    assert_eq!(role(i32::MIN), None);
    assert_eq!(role(ipc::win32_gdi::SYSTEM_COLOR_COUNT as i32), None);
    assert_eq!(role(i32::MAX), None);
}

#[test]
fn every_documented_index_names_its_role() {
    assert_eq!(role(0), Some(SystemColor::Scrollbar));
    assert_eq!(role(2), Some(SystemColor::ActiveCaption));
    assert_eq!(role(9), Some(SystemColor::CaptionText));
    assert_eq!(role(15), Some(SystemColor::Face));
    assert_eq!(role(ipc::win32_gdi::SYSTEM_COLOR_COUNT as i32 - 1), Some(SystemColor::MenuBar));
}

#[test]
fn a_count_that_is_not_positive_changes_nothing() {
    assert!(!admitted(0));
    assert!(!admitted(-1));
    assert!(admitted(1));
}
