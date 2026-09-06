use super::*;
use crate::win32_window::WindowRect;

fn window(state: &mut WindowManager, parent: Option<WindowId>) -> WindowId {
    let id = state.create(7, parent, 0x1000).unwrap();
    state.set_visible(id, true).unwrap();
    state.set_rect(id, WindowRect { left: 0, top: 0, right: 10, bottom: 10 }).unwrap();
    state.invalidate(id, None).unwrap();
    id
}

#[test]
fn redraw_root_first_then_topmost_child_without_consuming_damage() {
    let mut state = WindowManager::new();
    let root = window(&mut state, None);
    let low = window(&mut state, Some(root));
    let high = window(&mut state, Some(root));
    let leaf = window(&mut state, Some(high));
    assert_eq!(state.next_pending_paint(root, None, PaintChildren::All), Ok(Some(root)));
    assert_eq!(state.next_pending_paint(root, Some(root), PaintChildren::All), Ok(Some(high)));
    assert_eq!(state.next_pending_paint(root, Some(high), PaintChildren::All), Ok(Some(leaf)));
    assert_eq!(state.next_pending_paint(root, Some(leaf), PaintChildren::All), Ok(Some(low)));
    assert_eq!(state.next_pending_paint(root, Some(low), PaintChildren::All), Ok(None));
    assert!(state.begin_paint(root).unwrap().is_some());
}

#[test]
fn redraw_visibility_minimized_and_clipchildren_control_descent() {
    let mut state = WindowManager::new();
    let root = window(&mut state, None);
    let child = window(&mut state, Some(root));
    assert_eq!(state.next_pending_paint(root, Some(root), PaintChildren::None), Ok(None));
    assert_eq!(state.next_pending_paint(root, Some(root), PaintChildren::Default), Ok(None));
    state.set_window_styles(root, WS_CLIPCHILDREN, 0).unwrap();
    assert_eq!(state.next_pending_paint(root, Some(root), PaintChildren::Default), Ok(Some(child)));
    state.set_window_styles(root, WS_MINIMIZE | WS_CLIPCHILDREN, 0).unwrap();
    assert_eq!(state.next_pending_paint(root, Some(root), PaintChildren::All), Ok(None));
    state.set_window_styles(root, 0, 0).unwrap();
    state.set_visible(child, false).unwrap();
    assert_eq!(state.next_pending_paint(root, Some(root), PaintChildren::All), Ok(None));
    state.set_visible(root, false).unwrap();
    assert_eq!(state.next_pending_paint(root, None, PaintChildren::All), Ok(None));
}

#[test]
fn redraw_revalidates_pending_region_and_cursor_lifetime() {
    let mut state = WindowManager::new();
    let root = window(&mut state, None);
    let child = window(&mut state, Some(root));
    state.begin_paint(root).unwrap(); state.end_paint(root).unwrap();
    assert_eq!(state.next_pending_paint(root, None, PaintChildren::All), Ok(Some(child)));
    state.begin_paint(child).unwrap(); state.end_paint(child).unwrap();
    assert_eq!(state.next_pending_paint(root, None, PaintChildren::All), Ok(None));
    state.invalidate(child, None).unwrap();
    assert_eq!(state.next_pending_paint(root, None, PaintChildren::All), Ok(Some(child)));
    state.destroy(child).unwrap();
    assert_eq!(state.next_pending_paint(root, Some(child), PaintChildren::All), Ok(None));
    let stranger = window(&mut state, None);
    assert_eq!(state.next_pending_paint(root, Some(stranger), PaintChildren::All), Err(WindowError::InvalidParent));
    state.destroy(root).unwrap();
    assert_eq!(state.next_pending_paint(root, None, PaintChildren::All), Err(WindowError::NoSuchWindow));
}

#[test]
fn erase_allchildren_bypasses_in_tree_dirty_parent_but_not_external_ancestor() {
    // Wine 10.20 server/window.c get_window_update_flags: ALLCHILDREN suppresses
    // restart ancestor delay, not the dirty-ancestor check above the scan root.
    use crate::win32_window::{RDW_INVALIDATE,RDW_ERASE};
    let mut state=WindowManager::new();let root=window(&mut state,None);let child=window(&mut state,Some(root));
    for id in [root,child] {state.redraw_damage(id,None,RDW_INVALIDATE|RDW_ERASE,false).unwrap();}
    assert_eq!(state.next_pending_erase(root,None,PaintChildren::All),Ok(Some(root)));
    state.take_erase_damage(root).unwrap();
    assert_eq!(state.next_pending_erase(root,Some(root),PaintChildren::All),Ok(Some(child)));
    assert_eq!(state.next_pending_erase(root,Some(root),PaintChildren::Default),Ok(None));
    assert_eq!(state.next_pending_erase(child,None,PaintChildren::All),Ok(None));
    state.set_window_styles(root,WS_CLIPCHILDREN,0).unwrap();
    assert_eq!(state.next_pending_erase(child,None,PaintChildren::All),Ok(Some(child)));
}
