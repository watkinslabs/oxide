//! Pending update coverage and region complexity.
use super::super::super::*;
use super::region_complexity;
use crate::win32_gdi::{COMPLEX_REGION, NULL_REGION, SIMPLE_REGION};

fn window(state: &mut WindowManager) -> WindowId {
    let id = state.create(7, None, 0).unwrap();
    state.set_rect(id, WindowRect { left: 0, top: 0, right: 100, bottom: 80 }).unwrap();
    id
}

#[test]
fn a_window_with_nothing_pending_reports_an_empty_update_region() {
    let mut state = WindowManager::new();
    let id = window(&mut state);
    assert!(state.update_region(id).unwrap().is_empty());
    assert_eq!(state.update_rect(id).unwrap(), None);
}

#[test]
fn an_invalidated_rectangle_becomes_the_update_box() {
    let mut state = WindowManager::new();
    let id = window(&mut state);
    state.invalidate(id, Some(WindowRect { left: 10, top: 20, right: 30, bottom: 40 })).unwrap();
    assert_eq!(state.update_rect(id).unwrap(), Some(WindowRect { left: 10, top: 20, right: 30, bottom: 40 }));
}

#[test]
fn update_coverage_is_clipped_to_the_client_area() {
    let mut state = WindowManager::new();
    let id = window(&mut state);
    state.invalidate(id, Some(WindowRect { left: -50, top: -50, right: 500, bottom: 500 })).unwrap();
    assert_eq!(state.update_rect(id).unwrap(), Some(WindowRect { left: 0, top: 0, right: 100, bottom: 80 }));
}

#[test]
fn an_unknown_window_has_no_update_region() {
    let state = WindowManager::new();
    let id = WindowId::from_raw(9).unwrap();
    assert_eq!(state.update_region(id).err(), Some(WindowError::NoSuchWindow));
}

#[test]
fn complexity_separates_empty_exact_and_multi_rectangle_coverage() {
    assert_eq!(region_complexity(&PaintRegion::default()), NULL_REGION);
    let single = PaintRegion::from_rect(WindowRect { left: 0, top: 0, right: 10, bottom: 10 }).unwrap();
    assert_eq!(region_complexity(&single), SIMPLE_REGION);
    let split = PaintRegion::from_rects(&[WindowRect { left: 0, top: 0, right: 10, bottom: 10 },
        WindowRect { left: 40, top: 40, right: 50, bottom: 50 }]).unwrap();
    assert_eq!(region_complexity(&split), COMPLEX_REGION);
}
