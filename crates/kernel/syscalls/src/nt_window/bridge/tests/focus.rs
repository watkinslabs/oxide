use super::*;
const CHILD_TID: u64 = 23;
const ROOT_TID: u64 = 17;
const WS_CHILD: u32 = 0x4000_0000;
const WM_ACTIVATE: u32 = 0x0006;
const WM_ACTIVATEAPP: u32 = 0x001c;

fn setup() -> (WindowManager, WindowId, WindowId) {
    let mut state = WindowManager::new();
    let root = state.create(ROOT_TID, None, 0).unwrap();
    let child = state.create(CHILD_TID, Some(root), 0).unwrap();
    state.set_window_styles(child, WS_CHILD, 0).unwrap();
    state.set_focus(CHILD_TID, Some(child)).unwrap();
    drain(&mut state, CHILD_TID);
    (state, root, child)
}
fn drain(state: &mut WindowManager, tid: u64) -> Vec<WinMessage> {
    let mut out = Vec::new();
    while let Some(message) = state.peek_for_thread(tid, gui::MessageFilter { hwnd: None, first: 0, last: 0 }, true) { out.push(message); }
    out
}
fn focus(state: &mut WindowManager, id: WindowId, active: bool) -> bool {
    let record = Record::new(Opcode::Focus, 1, id.raw() as u64, (active as u32).to_le_bytes().to_vec()).unwrap();
    apply_event(state, &record, |_, _, _, _, _, _| false)
}

#[test]
fn top_level_activation_preserves_focused_child_then_restores_it_after_deactivation() {
    let (mut state, root, child) = setup();
    assert!(focus(&mut state, root, true));
    assert_eq!(state.active_window(), Some(root));
    assert_eq!(state.focused(), Some(child));
    assert!(drain(&mut state, CHILD_TID).is_empty());
    assert_eq!(drain(&mut state, ROOT_TID).iter().map(|m| m.message).collect::<Vec<_>>(),
        alloc::vec![WM_ACTIVATEAPP, gui::WM_NCACTIVATE, WM_ACTIVATE]);
    assert!(focus(&mut state, root, false));
    assert_eq!(state.active_window(), None);
    assert_eq!(state.focused(), None);
    assert_eq!(state.get(root).unwrap().last_focus, Some(child));
    assert_eq!(drain(&mut state, CHILD_TID)[0].message, gui::WM_KILLFOCUS);
    let lost = drain(&mut state, ROOT_TID);
    assert_eq!(lost.iter().map(|m| m.message).collect::<Vec<_>>(), alloc::vec![gui::WM_NCACTIVATE, WM_ACTIVATE, WM_ACTIVATEAPP]);
    assert!(lost.iter().all(|m| m.wparam == 0));
    assert!(focus(&mut state, root, true));
    assert_eq!(state.focused(), Some(child));
    assert_eq!(drain(&mut state, CHILD_TID)[0].message, gui::WM_SETFOCUS);
}

#[test]
fn duplicate_and_stale_deactivation_are_idempotent_and_child_records_rejected() {
    let (mut state, root, child) = setup();
    let other = state.create(ROOT_TID, None, 0).unwrap();
    assert!(focus(&mut state, root, true)); drain(&mut state, ROOT_TID);
    assert!(focus(&mut state, root, true));
    assert!(focus(&mut state, other, false));
    assert!(!focus(&mut state, child, true));
    assert_eq!(state.active_window(), Some(root)); assert_eq!(state.focused(), Some(child));
    assert!(drain(&mut state, ROOT_TID).is_empty());
}

#[test]
fn focus_batch_preflights_other_thread_before_changing_any_state_or_queue() {
    let (mut state, root, child) = setup();
    assert!(focus(&mut state, root, true)); drain(&mut state, ROOT_TID);
    let message = WinMessage { hwnd: Some(child), message: gui::WM_CLOSE, wparam: 0, lparam: 0 };
    while state.post_to_window(child, message).is_ok() {}
    assert!(!focus(&mut state, root, false));
    assert_eq!(state.active_window(), Some(root)); assert_eq!(state.focused(), Some(child));
    assert_eq!(state.get(root).unwrap().last_focus, None);
    assert!(drain(&mut state, ROOT_TID).is_empty());
}

#[test]
fn destroying_remembered_child_falls_back_to_root_and_root_destruction_clears_active() {
    let (mut state, root, child) = setup();
    assert!(focus(&mut state, root, true));
    assert!(focus(&mut state, root, false));
    state.destroy(child).unwrap();
    assert_eq!(state.get(root).unwrap().last_focus, None);
    assert!(focus(&mut state, root, true));
    assert_eq!(state.focused(), Some(root));
    state.destroy(root).unwrap();
    assert_eq!(state.active_window(), None); assert_eq!(state.focused(), None);
    assert!(!focus(&mut state, root, true));
}

#[test]
fn switching_top_levels_notifies_owner_threads_and_restores_each_descendant() {
    const SECOND_TID: u64 = 29;
    let (mut state, root, child) = setup();
    let second = state.create(SECOND_TID, None, 0).unwrap();
    assert!(focus(&mut state, root, true)); drain(&mut state, ROOT_TID);
    assert!(focus(&mut state, second, true));
    assert_eq!(state.active_window(), Some(second)); assert_eq!(state.focused(), Some(second));
    assert_eq!(state.get(root).unwrap().last_focus, Some(child));
    let old = drain(&mut state, ROOT_TID);
    let lost = old.iter().find(|m| m.message == WM_ACTIVATEAPP).unwrap();
    assert_eq!((lost.wparam, lost.lparam), (0, SECOND_TID as i64));
    let new = drain(&mut state, SECOND_TID);
    let gained = new.iter().find(|m| m.message == WM_ACTIVATEAPP).unwrap();
    assert_eq!((gained.wparam, gained.lparam), (1, ROOT_TID as i64));
    assert!(focus(&mut state, root, true));
    assert_eq!(state.focused(), Some(child));
}

#[test]
fn owned_popup_is_not_a_descendant_focus_of_its_owner() {
    let (mut state, root, _) = setup();
    let popup = state.create(ROOT_TID, Some(root), 0).unwrap();
    state.set_focus(ROOT_TID, Some(popup)).unwrap();
    assert!(focus(&mut state, root, true));
    assert_eq!(state.focused(), Some(root));
    assert!(focus(&mut state, popup, true));
    assert_eq!(state.active_window(), Some(popup));
    assert_eq!(state.focused(), Some(popup));
}
