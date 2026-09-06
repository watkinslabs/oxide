use super::*;
use crate::win32_window::{WindowRect, MessageFilter, QueueResult, WM_PAINT};

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

#[test]
fn showing_a_window_with_geometry_leaves_it_pending_paint() {
    // Measured in the guest: Notepad creates its window, ShowWindow is reached
    // for it, it enters its message loop, and no paint ever happens, so the
    // desktop stays empty. Showing a window that has real geometry must leave
    // it needing paint, or nothing downstream can ever draw it.
    let mut state = WindowManager::new();
    let id = state.create(7, None, 0x1000).unwrap();
    state.set_rect(id, WindowRect { left: 0, top: 0, right: 729, bottom: 546 }).unwrap();
    assert_eq!(state.show(7, id, true), Ok(false));
    assert_eq!(state.next_pending_paint(id, None, PaintChildren::All), Ok(Some(id)));
}

#[test]
fn showing_a_window_with_no_geometry_yet_leaves_nothing_to_paint() {
    // The complement: a window with no extent has nothing to damage, and must
    // not be reported as paintable. This is what keeps the assertion above
    // from being satisfied by simply always invalidating.
    let mut state = WindowManager::new();
    let id = state.create(7, None, 0x1000).unwrap();
    assert_eq!(state.show(7, id, true), Ok(false));
    assert_eq!(state.next_pending_paint(id, None, PaintChildren::All), Ok(None));
}

// The full cycle an application actually performs, driven hosted because the
// guest costs eight minutes per question: create, show, retrieve, paint,
// retrieve again. Measured in the guest, WM_PAINT for the main window repeats
// without bound - tens of thousands of deliveries at one timestamp - so
// something in this cycle fails to clear the damage.
#[test]
fn a_painted_window_stops_asking_to_be_painted() {
    let mut state = WindowManager::new();
    let id = state.create(7, None, 0x1000).unwrap();
    state.set_rect(id, WindowRect { left: 0, top: 0, right: 729, bottom: 546 }).unwrap();
    state.show(7, id, true).unwrap();

    let filter = MessageFilter { hwnd: None, first: 0, last: 0 };
    // First retrieval hands the application its WM_PAINT.
    let first = state.take_for_thread(7, filter);
    assert!(matches!(first, QueueResult::Message(m) if m.message == WM_PAINT && m.hwnd == Some(id)),
        "a shown window must be offered WM_PAINT, got {first:?}");

    // The application paints, which is what validates the damage.
    state.begin_paint(id).unwrap();
    state.end_paint(id).unwrap();

    // It must not be asked again. If it is, the application repaints forever
    // and never makes progress, which is exactly what the guest shows.
    let second = state.take_for_thread(7, filter);
    assert!(matches!(second, QueueResult::Empty),
        "a painted window must stop asking to be painted, got {second:?}");
}

#[test]
fn deferring_a_paint_to_the_default_handler_still_clears_the_damage() {
    // The guest's actual sequence: the application does not paint itself, it
    // hands WM_PAINT to the default handler. That must consume the damage, or
    // the same message is offered again immediately and the application never
    // makes progress - which is exactly the unbounded repeat measured.
    let mut state = WindowManager::new();
    let id = state.create(7, None, 0x1000).unwrap();
    state.set_rect(id, WindowRect { left: 0, top: 0, right: 729, bottom: 546 }).unwrap();
    state.show(7, id, true).unwrap();
    let filter = MessageFilter { hwnd: None, first: 0, last: 0 };

    let first = state.take_for_thread(7, filter);
    assert!(matches!(first, QueueResult::Message(m) if m.message == WM_PAINT));

    // What default handling asks for, and what the kernel then performs.
    assert_eq!(crate::win32_window::default_window_proc(WM_PAINT),
        crate::win32_window::DefaultWindowResult::ValidatePaint);
    state.begin_paint(id).unwrap();
    state.end_paint(id).unwrap();

    assert!(matches!(state.take_for_thread(7, filter), QueueResult::Empty),
        "default paint handling must leave nothing to repaint");
}

#[test]
fn a_created_window_is_told_the_size_it_was_created_with() {
    // Measured in the guest: Notepad received WM_CREATE, WM_MOVE, WM_PAINT,
    // WM_SHOWWINDOW and WM_NCCREATE, but never WM_SIZE, so the EDIT control it
    // lays out from that size stayed 0x0 and the window drew nothing.
    let mut state = WindowManager::new();
    let id = state.create(7, None, 0x1000).unwrap();
    state.set_rect(id, WindowRect { left: 0, top: 0, right: 729, bottom: 546 }).unwrap();
    state.notify_created_geometry(id).unwrap();
    let filter = MessageFilter { hwnd: None, first: 0, last: 0 };
    let msg = state.take_for_thread(7, filter);
    match msg {
        QueueResult::Message(m) => {
            assert_eq!(m.message, crate::win32_window::WM_SIZE);
            assert_eq!(m.hwnd, Some(id));
            // The low and high halves carry the client width and height.
            assert_eq!(m.lparam & 0xffff, 729);
            assert_eq!((m.lparam >> 16) & 0xffff, 546);
        }
        other => panic!("a created window must be told its size, got {other:?}"),
    }
}

#[test]
fn a_window_with_no_extent_is_told_nothing() {
    // A zero-sized window has no size to report, and inventing one would make
    // a control lay itself out against a size the window does not have.
    let mut state = WindowManager::new();
    let id = state.create(7, None, 0x1000).unwrap();
    state.notify_created_geometry(id).unwrap();
    let filter = MessageFilter { hwnd: None, first: 0, last: 0 };
    assert!(matches!(state.take_for_thread(7, filter), QueueResult::Empty));
}
