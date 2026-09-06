use super::*;
use crate::win32_gdi::{BrushStyle, TYPE_BRUSH};

#[test]
fn system_brush_identity_is_cached_live_and_typed() {
    let mut state = GdiManager::new();
    let window = state.system_brush(SystemColor::Window).unwrap();
    assert_eq!(state.system_brush(SystemColor::Window), Ok(window));
    assert_eq!(window & 0x7f0000, TYPE_BRUSH);
    assert!(state.contains_object(window));
    assert!(state.live_handles().contains(&window));
    assert_eq!(state.brush_style(window, 0), Ok(BrushStyle::Solid(0x00ff_ffff)));
    let face = state.system_brush(SystemColor::Face).unwrap();
    assert_ne!(window, face);
    assert_eq!(state.brush_style(face, 0), Ok(BrushStyle::Solid(0x00d4_d0c8)));
    assert!(state.is_system_brush(window));
    assert!(!state.is_system_brush(window ^ 0x10000));
    assert_eq!(SystemColor::from_index(5), Some(SystemColor::Window));
    assert_eq!(SystemColor::from_index(8), Some(SystemColor::WindowText));
    assert_eq!(SystemColor::from_index(15), Some(SystemColor::Face));
    assert_eq!(SystemColor::from_index(u32::MAX), None);
    for (index, color) in [(0, 0xd4d0c8), (21, 0x404040), (22, 0xd4d0c8)] {
        let role = SystemColor::from_index(index).unwrap();
        assert_eq!(role.color(), color);
        let brush = state.system_brush(role).unwrap();
        state.delete_object(brush).unwrap();
        assert_eq!(state.system_brush(role), Ok(brush));
        assert_eq!(state.brush_style(brush, 0), Ok(BrushStyle::Solid(color)));
    }
}

#[test]
fn system_brush_deletion_never_removes_unselected_or_selected_identity() {
    let mut state = GdiManager::new();
    let brush = state.system_brush(SystemColor::Window).unwrap();
    state.delete_brush(brush).unwrap();
    assert!(state.contains_object(brush));
    let dc = state.create_dc(2, 2).unwrap();
    state.select_brush(dc, brush).unwrap();
    state.delete_object(brush).unwrap();
    state.delete_object(dc).unwrap();
    assert!(state.contains_object(brush));
    assert_eq!(state.system_brush(SystemColor::Window), Ok(brush));
    let ordinary = state.create_solid_brush(0xffffff).unwrap();
    state.delete_brush(ordinary).unwrap();
    assert!(!state.contains_object(ordinary));
}

#[test]
fn system_brush_handle_exhaustion_never_publishes_fake_cache_entry() {
    let mut state = GdiManager::new();
    state.next = super::super::SLOT_LIMIT;
    assert_eq!(state.system_brush(SystemColor::Window), Err(GdiError::HandleLimit));
    assert!(!state.is_system_brush(0));
    assert!(state.system_brushes.handles.iter().all(Option::is_none));
}
