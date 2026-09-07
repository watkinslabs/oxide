//! Damage a child control records while its own thread is inside message
//! retrieval must still reach that thread as WM_PAINT (`31fl§5`).
//!
//! Geometry mirrors the framed Notepad the acceptance run drives: the frame
//! carries a nonclient border, caption and menu band, so the child control's
//! rectangle sits at a nonzero client origin inside its parent.
use super::*;
use crate::win32_window::{MessageFilter, PaintRegion, QueueResult, WindowRect, WM_PAINT,
    queue_status::{QS_ALLINPUT, QS_PAINT}, RDW_ERASE, RDW_INVALIDATE};

const WS_VISIBLE: u32 = 0x1000_0000;
const WS_CHILD: u32 = 0x4000_0000;
const WM_KEYDOWN: u32 = 0x0100;
const WM_KEYUP: u32 = 0x0101;
const WM_CHAR: u32 = 0x0102;
const ANY: MessageFilter = MessageFilter { hwnd: None, first: 0, last: 0 };
const TID: u64 = 7;
/// Characters the acceptance run injects into the located window.
const TOKEN: &[u8] = b"OXIDE-NOTEPAD";
/// The frame rectangle the acceptance run locates on the desktop.
const FRAME: WindowRect = WindowRect { left: 261, top: 122, right: 582, bottom: 768 };
/// Client area left by one border, one caption and the menu band.
const FRAME_CLIENT: WindowRect = WindowRect { left: 262, top: 152, right: 581, bottom: 767 };
/// Control rectangle, in the frame's client coordinates.
const EDIT: WindowRect = WindowRect { left: 0, top: 0, right: 319, bottom: 615 };
/// The line the control rewrites after a character reaches it.
const LINE: WindowRect = WindowRect { left: 0, top: 0, right: 319, bottom: 16 };

fn notepad() -> (WindowManager, WindowId, WindowId) {
    let mut state = WindowManager::new();
    let frame = state.create(TID, None, 0x1000).unwrap();
    state.set_visible(frame, true).unwrap();
    state.set_style_bits(frame, WS_VISIBLE, 0).unwrap();
    state.set_rect(frame, FRAME).unwrap();
    state.set_client_rect(frame, FRAME_CLIENT).unwrap();
    let edit = state.create(TID, Some(frame), 0x2000).unwrap();
    state.set_visible(edit, true).unwrap();
    state.set_style_bits(edit, WS_VISIBLE | WS_CHILD, 0).unwrap();
    state.set_rect(edit, EDIT).unwrap();
    (state, frame, edit)
}

/// Consume the paints creation and first show leave behind. # C: O(messages)
fn drain(state: &mut WindowManager) {
    for _ in 0..64 {
        match state.take_for_thread(TID, ANY) {
            QueueResult::Message(found) if found.message == WM_PAINT => {
                let id = found.hwnd.unwrap();
                state.begin_paint(id).unwrap(); state.end_paint(id).unwrap();
            }
            QueueResult::Message(_) => {}
            _ => return,
        }
    }
}

#[test]
fn the_control_rectangle_still_takes_damage_under_the_frame_client_origin() {
    let (state, _frame, edit) = notepad();
    assert_eq!(state.visible_paint_rect(edit, false), Some(EDIT), "the control exposes its own client area");
}

#[test]
fn a_burst_of_keys_is_retrieved_before_the_paint_the_typing_damaged() {
    let (mut state, _frame, edit) = notepad();
    drain(&mut state);
    assert!(matches!(state.take_for_thread(TID, ANY), QueueResult::Empty), "clean start");
    for byte in TOKEN {
        for (message, wparam) in [(WM_KEYDOWN, *byte as u64), (WM_CHAR, *byte as u64), (WM_KEYUP, *byte as u64)] {
            state.post_input_to_window(edit, WinMessage { hwnd: Some(edit), message, wparam, lparam: 0 }).unwrap();
        }
    }
    let region = PaintRegion::from_rect(LINE).unwrap();
    let mut keys = 0usize;
    let mut invalidated = false;
    let mut painted = None;
    for _ in 0..(TOKEN.len() * 3 + 8) {
        match state.take_for_thread(TID, ANY) {
            QueueResult::Message(found) if found.message == WM_PAINT => { painted = Some(found.hwnd); break; }
            QueueResult::Message(found) => {
                keys += 1;
                // The control invalidates the line it rewrote from inside its
                // own handling of the first character, between two retrievals.
                if found.message == WM_CHAR && !invalidated {
                    invalidated = true;
                    state.redraw_tree(edit, Some(&region), RDW_INVALIDATE | RDW_ERASE, |_, _, region| region.try_copy()).unwrap();
                    assert!(state.queue_satisfies(TID, QS_PAINT), "the damage is a wake reason for the parked pump");
                    assert!(state.queue_satisfies(TID, QS_ALLINPUT), "the paint counts inside the pump's own mask");
                }
            }
            other => panic!("the queue emptied without a paint after {keys} keys: {other:?}"),
        }
    }
    assert_eq!(keys, TOKEN.len() * 3, "every injected key is retrieved before the paint");
    assert_eq!(painted, Some(Some(edit)), "the damaged control receives the paint");
    assert_eq!(state.begin_paint(edit), Ok(Some(LINE)));
}

/// Where the frame is created, before the window manager places it.
const CREATED_FRAME: WindowRect = WindowRect { left: 0, top: 0, right: 321, bottom: 646 };
/// The client area that creation's nonclient calculation leaves, in the same
/// coordinates as the window rectangle it was computed from.
const CREATED_CLIENT: WindowRect = WindowRect { left: 1, top: 30, right: 320, bottom: 645 };

/// The same window before the window manager places it on the desktop.
fn created_notepad() -> (WindowManager, WindowId, WindowId) {
    let mut state = WindowManager::new();
    let frame = state.create(TID, None, 0x1000).unwrap();
    state.set_visible(frame, true).unwrap();
    state.set_style_bits(frame, WS_VISIBLE, 0).unwrap();
    state.set_rect(frame, CREATED_FRAME).unwrap();
    state.set_client_rect(frame, CREATED_CLIENT).unwrap();
    let edit = state.create(TID, Some(frame), 0x2000).unwrap();
    state.set_visible(edit, true).unwrap();
    state.set_style_bits(edit, WS_VISIBLE | WS_CHILD, 0).unwrap();
    state.set_rect(edit, EDIT).unwrap();
    (state, frame, edit)
}

#[test]
fn a_moved_frame_carries_its_client_rectangle_so_the_control_still_takes_damage() {
    let (mut state, frame, edit) = created_notepad();
    drain(&mut state);
    let request = crate::win32_window::WindowPosition { window: frame, rect: FRAME, client: None,
        order: None, visible: None, flags: 0, notify_geometry: false };
    state.apply_position(TID, request).unwrap();
    // The client rectangle moves with the window it belongs to, so the two
    // still name one space and the control's own client coordinates survive
    // the crop through its parent.
    assert_eq!(state.get(frame).unwrap().client_rect,
        Some(WindowRect { left: 262, top: 152, right: 581, bottom: 767 }));
    assert_eq!(state.visible_paint_rect(edit, false), Some(EDIT));
    let region = PaintRegion::from_rect(LINE).unwrap();
    state.redraw_tree(edit, Some(&region), RDW_INVALIDATE | RDW_ERASE, |_, _, region| region.try_copy()).unwrap();
    assert!(state.dirty_windows().contains(&edit), "the typed line is damage the control still owes");
    // The move exposes the frame, whose paint is offered root-before-child;
    // the control's own paint follows it.
    let mut painted = None;
    for _ in 0..8 {
        match state.take_for_thread(TID, ANY) {
            QueueResult::Message(found) if found.message == WM_PAINT => {
                let id = found.hwnd.unwrap();
                if id == edit { painted = Some(id); break; }
                state.begin_paint(id).unwrap(); state.end_paint(id).unwrap();
            }
            QueueResult::Message(_) => {}
            other => panic!("the moved frame lost the control's paint: {other:?}"),
        }
    }
    assert_eq!(painted, Some(edit), "the control's own paint follows its frame's");
    assert_eq!(state.begin_paint(edit), Ok(Some(LINE)));
}
