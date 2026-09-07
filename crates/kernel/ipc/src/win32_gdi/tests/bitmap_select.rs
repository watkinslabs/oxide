//! Binding a bitmap to a memory device context.
use super::*;
use super::super::{GdiManager, GdiError};

#[test]
fn only_a_memory_context_selects_a_bitmap_and_it_takes_the_bitmaps_extent() {
    let mut gdi = GdiManager::new();
    let memory = gdi.create_dc(2, 2).unwrap();
    let display = gdi.create_display_dc(2, 2).unwrap();
    let bitmap = gdi.create_bitmap(6, 5, 1, 32, None).unwrap();
    assert_eq!(gdi.select_bitmap(display, bitmap), Err(GdiError::NoSuchObject));
    // The first selection replaces the context's stock bitmap, reported as none.
    assert_eq!(gdi.select_bitmap(memory, bitmap), Ok(0));
    assert_eq!(gdi.dc_bitmap(memory), Some(bitmap));
    assert_eq!(gdi.text_state(memory).map(|state| (state.width, state.height)), Ok((6, 5)));
}

#[test]
fn selecting_the_bitmap_a_context_already_holds_changes_nothing() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(2, 2).unwrap();
    let bitmap = gdi.create_bitmap(2, 2, 1, 32, None).unwrap();
    gdi.select_bitmap(dc, bitmap).unwrap();
    assert_eq!(gdi.select_bitmap(dc, bitmap), Ok(bitmap));
    let second = gdi.create_bitmap(3, 3, 1, 32, None).unwrap();
    assert_eq!(gdi.select_bitmap(dc, second), Ok(bitmap));
}

#[test]
fn a_bitmap_already_selected_elsewhere_is_refused() {
    let mut gdi = GdiManager::new();
    let first = gdi.create_dc(2, 2).unwrap();
    let second = gdi.create_dc(2, 2).unwrap();
    let bitmap = gdi.create_bitmap(2, 2, 1, 32, None).unwrap();
    gdi.select_bitmap(first, bitmap).unwrap();
    assert_eq!(gdi.select_bitmap(second, bitmap), Err(GdiError::NoSuchObject));
    assert_eq!(gdi.dc_bitmap(second), None);
}

#[test]
fn a_device_dependent_depth_the_device_neither_matches_nor_emulates_is_refused() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(2, 2).unwrap();
    for depth in [4, 8, 16, 24] {
        let bitmap = gdi.create_bitmap(2, 2, 1, depth, None).unwrap();
        assert_eq!(gdi.select_bitmap(dc, bitmap), Err(GdiError::InvalidDimensions));
    }
    // Monochrome and the device's own depth are both selectable.
    for depth in [1, 32] {
        let bitmap = gdi.create_bitmap(2, 2, 1, depth, None).unwrap();
        assert!(gdi.select_bitmap(dc, bitmap).is_ok());
    }
    assert_eq!(gdi.select_bitmap(dc, 99), Err(GdiError::NoSuchObject));
    assert_eq!(gdi.select_bitmap(99, 1), Err(GdiError::NoSuchObject));
}

#[test]
fn a_selected_bitmap_survives_deletion_until_its_context_releases_it() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(2, 2).unwrap();
    let bitmap = gdi.create_bitmap(2, 2, 1, 32, None).unwrap();
    let other = gdi.create_bitmap(2, 2, 1, 32, None).unwrap();
    gdi.select_bitmap(dc, bitmap).unwrap();
    assert_eq!(gdi.delete_object(bitmap), Ok(()));
    assert!(gdi.contains_object(bitmap));
    assert_eq!(gdi.select_bitmap(dc, other), Ok(bitmap));
    assert!(!gdi.contains_object(bitmap));
}
