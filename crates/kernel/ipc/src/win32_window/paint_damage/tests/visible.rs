//! Damage a window can never repaint is damage it must never be offered.
use super::super::super::*;
use alloc::vec::Vec;

fn rect(l: i32, t: i32, r: i32, b: i32) -> WindowRect { WindowRect { left: l, top: t, right: r, bottom: b } }
const TID: u64 = 7;

fn tree(child: WindowRect) -> (WindowManager, WindowId, WindowId) {
    let mut state = WindowManager::new();
    let root = state.create(TID, None, 0x1234).unwrap();
    state.set_rect(root, rect(0, 0, 300, 200)).unwrap();
    let bar = state.create(TID, Some(root), 0x2345).unwrap();
    state.set_rect(bar, child).unwrap();
    state.set_visible(bar, true).unwrap();
    state.show(TID, root, true).unwrap();
    (state, root, bar)
}

/// One full pump: every paint the thread is offered, painted and finished,
/// bounded so a window that keeps re-offering its paint is a failure and not
/// a hang.
fn drain(state: &mut WindowManager) -> Vec<WindowId> {
    let filter = MessageFilter { hwnd: None, first: 0, last: 0 };
    let mut painted = Vec::new();
    for _ in 0..32 {
        let Some(message) = state.take_pending_paint(TID, filter, true) else { break; };
        let id = message.hwnd.unwrap();
        state.begin_paint(id).unwrap();
        state.end_paint(id).unwrap();
        painted.push(id);
    }
    painted
}

#[test]
fn a_zero_sized_child_takes_no_damage_and_is_offered_no_paint() {
    let (mut state, root, bar) = tree(rect(0, 0, 0, 0));
    state.invalidate(bar, None).unwrap();
    state.redraw_damage(bar, None, RDW_INVALIDATE | RDW_ERASE | RDW_FRAME, false).unwrap();
    state.redraw_damage(bar, None, RDW_INTERNALPAINT, false).unwrap();
    assert!(!state.dirty_windows().contains(&bar));
    assert_eq!(drain(&mut state), alloc::vec![root]);
}

#[test]
fn a_child_outside_its_parent_client_area_takes_no_damage() {
    let (mut state, root, bar) = tree(rect(0, 400, 300, 424));
    state.invalidate(bar, None).unwrap();
    assert!(!state.dirty_windows().contains(&bar));
    assert_eq!(drain(&mut state), alloc::vec![root]);
    // The part that does overlap is the only part that can be damaged.
    state.set_rect(bar, rect(0, 180, 300, 260)).unwrap();
    state.invalidate(bar, None).unwrap();
    assert_eq!(state.update_rect(bar).unwrap(), Some(rect(0, 0, 300, 20)));
}

#[test]
fn a_child_under_a_hidden_parent_takes_no_damage() {
    let (mut state, root, bar) = tree(rect(0, 100, 300, 124));
    drain(&mut state);
    state.show(TID, root, false).unwrap();
    state.invalidate(bar, None).unwrap();
    assert!(!state.dirty_windows().contains(&bar));
    assert!(state.pending_paint_message(TID).is_none());
}

// The pump must drain: every window that owed a paint painted exactly once,
// however many times the thread asks for a message afterwards.
#[test]
fn each_damaged_window_is_offered_one_paint_per_damage() {
    let (mut state, root, bar) = tree(rect(0, 100, 300, 124));
    state.invalidate(bar, None).unwrap();
    let mut painted = drain(&mut state);
    painted.sort_by_key(|id| id.raw());
    let mut expected = alloc::vec![root, bar];
    expected.sort_by_key(|id| id.raw());
    assert_eq!(painted, expected);
    assert!(drain(&mut state).is_empty());
}

// A layout that leaves a client rectangle behind on a window whose own
// rectangle went empty must not keep offering a paint the window can never
// service.
#[test]
fn a_stale_client_rect_on_an_empty_window_takes_no_damage() {
    let (mut state, root, bar) = tree(rect(0, 0, 0, 0));
    drain(&mut state);
    state.set_client_rect(bar, rect(0, 176, 300, 200)).unwrap();
    for _ in 0..4 { state.invalidate(bar, None).unwrap(); }
    assert!(!state.dirty_windows().contains(&bar));
    assert!(drain(&mut state).is_empty());
    let _ = root;
}
