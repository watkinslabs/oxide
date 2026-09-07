//! Typed text in a child control must reach a WM_PAINT retrieval (`31fl§5`).
use super::*;
use crate::win32_window::{MessageFilter, PaintRegion, QueueResult, WindowRect, WinMessage, WM_PAINT,
    RDW_ERASE, RDW_INVALIDATE};

const WS_VISIBLE: u32 = 0x1000_0000;
const WM_CHAR: u32 = 0x0102;
const ANY: MessageFilter = MessageFilter { hwnd: None, first: 0, last: 0 };
const TID: u64 = 7;

/// A framed top-level window with one child control covering its client area.
fn notepad() -> (WindowManager, WindowId, WindowId) {
    let mut state = WindowManager::new();
    let frame = state.create(TID, None, 0x1000).unwrap();
    state.set_visible(frame, true).unwrap();
    state.set_style_bits(frame, WS_VISIBLE, 0).unwrap();
    state.set_rect(frame, WindowRect { left: 100, top: 100, right: 900, bottom: 700 }).unwrap();
    let edit = state.create(TID, Some(frame), 0x2000).unwrap();
    state.set_visible(edit, true).unwrap();
    state.set_style_bits(edit, WS_VISIBLE, 0).unwrap();
    state.set_rect(edit, WindowRect { left: 0, top: 0, right: 800, bottom: 580 }).unwrap();
    (state, frame, edit)
}

/// Drain the first paint the way a pump does, so the state under test is the
/// one a running application reaches before it is typed into.
fn drain(state: &mut WindowManager) {
    for _ in 0..8 {
        match state.take_for_thread(TID, ANY) {
            QueueResult::Message(found) if found.message == WM_PAINT => {
                let id = found.hwnd.unwrap();
                state.begin_paint(id).unwrap();
                state.end_paint(id).unwrap();
            }
            QueueResult::Message(_) => {}
            _ => return,
        }
    }
}

#[test]
fn typed_character_in_the_child_control_is_retrieved_as_a_child_paint() {
    let (mut state, _frame, edit) = notepad();
    drain(&mut state);
    assert!(matches!(state.take_for_thread(TID, ANY), QueueResult::Empty), "clean start");
    state.post_to_window(edit, WinMessage { hwnd: Some(edit), message: WM_CHAR, wparam: 0x41, lparam: 0 }).unwrap();
    // The control invalidates the line it rewrote, in its own client coordinates.
    let region = PaintRegion::from_rect(WindowRect { left: 0, top: 0, right: 800, bottom: 16 }).unwrap();
    state.redraw_tree(edit, Some(&region), RDW_INVALIDATE | RDW_ERASE, |_, _, region| region.try_copy()).unwrap();
    assert!(matches!(state.take_for_thread(TID, ANY), QueueResult::Message(found) if found.message == WM_CHAR));
    match state.take_for_thread(TID, ANY) {
        QueueResult::Message(found) => assert_eq!((found.message, found.hwnd), (WM_PAINT, Some(edit))),
        other => panic!("typed text produced no paint: {other:?}"),
    }
    assert_eq!(state.begin_paint(edit), Ok(Some(WindowRect { left: 0, top: 0, right: 800, bottom: 16 })));
}

#[test]
fn a_second_typed_character_after_a_completed_paint_paints_again() {
    let (mut state, _frame, edit) = notepad();
    drain(&mut state);
    let region = PaintRegion::from_rect(WindowRect { left: 0, top: 0, right: 800, bottom: 16 }).unwrap();
    for _ in 0..2 {
        state.redraw_tree(edit, Some(&region), RDW_INVALIDATE | RDW_ERASE, |_, _, region| region.try_copy()).unwrap();
        match state.take_for_thread(TID, ANY) {
            QueueResult::Message(found) => assert_eq!((found.message, found.hwnd), (WM_PAINT, Some(edit))),
            other => panic!("re-typed text produced no paint: {other:?}"),
        }
        state.begin_paint(edit).unwrap();
        state.end_paint(edit).unwrap();
    }
}

#[test]
fn a_no_remove_peek_between_the_keys_and_the_paint_keeps_the_paint() {
    let (mut state, _frame, edit) = notepad();
    drain(&mut state);
    let region = PaintRegion::from_rect(WindowRect { left: 0, top: 0, right: 800, bottom: 16 }).unwrap();
    state.redraw_tree(edit, Some(&region), RDW_INVALIDATE | RDW_ERASE, |_, _, region| region.try_copy()).unwrap();
    assert_eq!(state.peek_for_thread(TID, ANY, false).map(|m| (m.message, m.hwnd)), Some((WM_PAINT, Some(edit))));
    assert_eq!(state.peek_for_thread(TID, ANY, false).map(|m| (m.message, m.hwnd)), Some((WM_PAINT, Some(edit))));
    match state.take_for_thread(TID, ANY) {
        QueueResult::Message(found) => assert_eq!((found.message, found.hwnd), (WM_PAINT, Some(edit))),
        other => panic!("peek consumed the paint: {other:?}"),
    }
}
