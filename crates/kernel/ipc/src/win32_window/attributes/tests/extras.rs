//! Help context, layered attributes, window region and display affinity.
use super::*;

fn one() -> (WindowManager, WindowId) {
    let mut windows = WindowManager::new();
    let id = windows.create(1, None, 0).unwrap();
    windows.set_rect(id, WindowRect { left: 0, top: 0, right: 100, bottom: 50 }).unwrap();
    (windows, id)
}

#[test]
fn a_window_that_never_set_a_help_context_answers_zero() {
    let (mut windows, id) = one();
    assert_eq!(windows.help_context(id), 0);
    windows.set_help_context(id, 0x1234).unwrap();
    assert_eq!(windows.help_context(id), 0x1234);
    windows.destroy(id).unwrap();
    assert_eq!(windows.set_help_context(id, 1), Err(WindowError::NoSuchWindow));
}

#[test]
fn setting_layered_attributes_marks_the_window_layered() {
    let (mut windows, id) = one();
    assert_eq!(windows.layered_attributes(id), None);
    assert_eq!(windows.get(id).unwrap().ex_style & WS_EX_LAYERED, 0);
    let attributes = LayeredAttributes { color_key: 0x00ff_00ff, alpha: 0x80, flags: LWA_ALPHA | LWA_COLORKEY };
    windows.set_layered_attributes(id, attributes).unwrap();
    assert_eq!(windows.layered_attributes(id), Some(attributes));
    assert_ne!(windows.get(id).unwrap().ex_style & WS_EX_LAYERED, 0);
}

#[test]
fn a_per_pixel_update_needs_a_layered_window_with_no_attributes_and_a_known_flag() {
    let (mut windows, id) = one();
    assert_eq!(windows.admit_layered_update(id, 0, None), Err(WindowError::InvalidParameter));
    windows.set_ex_style_bits(id, WS_EX_LAYERED, 0).unwrap();
    assert_eq!(windows.admit_layered_update(id, 0, None), Ok(()));
    assert_eq!(windows.admit_layered_update(id, 0x1000, None), Err(WindowError::InvalidParameter));
    windows.set_layered_attributes(id, LayeredAttributes::default()).unwrap();
    assert_eq!(windows.admit_layered_update(id, 0, None), Err(WindowError::InvalidParameter));
}

#[test]
fn a_per_pixel_update_refuses_an_empty_size_and_an_unwanted_resize() {
    let (mut windows, id) = one();
    windows.set_ex_style_bits(id, WS_EX_LAYERED, 0).unwrap();
    assert_eq!(windows.admit_layered_update(id, 0, Some((0, 10))), Err(WindowError::InvalidParameter));
    assert_eq!(windows.admit_layered_update(id, 0, Some((100, 50))), Ok(()));
    assert_eq!(windows.admit_layered_update(id, 0, Some((120, 50))), Ok(()));
    assert_eq!(windows.admit_layered_update(id, ULW_EX_NORESIZE, Some((120, 50))), Err(WindowError::InvalidParameter));
    assert_eq!(windows.admit_layered_update(id, ULW_EX_NORESIZE, Some((100, 50))), Ok(()));
}

#[test]
fn a_window_region_installs_and_clears() {
    let (mut windows, id) = one();
    assert_eq!(windows.window_region(id), None);
    let rects = [WindowRect { left: 0, top: 0, right: 10, bottom: 10 }];
    windows.set_window_region(id, Some(&rects)).unwrap();
    assert_eq!(windows.window_region(id), Some(&rects[..]));
    windows.set_window_region(id, Some(&[])).unwrap();
    assert_eq!(windows.window_region(id), Some(&[][..]));
    windows.set_window_region(id, None).unwrap();
    assert_eq!(windows.window_region(id), None);
}

#[test]
fn display_affinity_answers_unprotected_for_a_live_window_and_reports_an_unknown_one() {
    let (mut windows, id) = one();
    assert_eq!(windows.display_affinity(id), Ok(WDA_NONE));
    windows.destroy(id).unwrap();
    assert_eq!(windows.display_affinity(id), Err(WindowError::NoSuchWindow));
}

#[test]
fn destroying_a_window_can_discard_its_attributes() {
    let (mut windows, id) = one();
    windows.set_help_context(id, 7).unwrap();
    windows.forget_attributes(id);
    assert_eq!(windows.help_context(id), 0);
}
