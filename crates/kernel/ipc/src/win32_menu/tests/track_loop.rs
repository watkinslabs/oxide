use super::*;
use crate::win32_menu::popup::{PopupHit, TPM_BUTTONDOWN};
use crate::win32_menu::track::{MF_MOUSESELECT, TrackEffect, WM_COMMAND, WM_INITMENUPOPUP};
use crate::win32_menu::{MenuId, MenuItem, MF_HILITE, MF_SEPARATOR};
use alloc::vec;

const OWNER: u32 = 7;
const WM_PAINT: u32 = 0x000f;

fn text(value: &str) -> Vec<u16> { value.encode_utf16().collect() }

/// One bar carrying a single popup, and the popup's own items.
fn chain() -> (MenuManager, u32, u32) {
    let mut menus = MenuManager::new();
    let bar = menus.create().unwrap();
    let popup = menus.create_popup().unwrap();
    menus.insert(bar, 0, MenuItem { id: 0, state: 0, text: text("&File"), submenu: Some(popup.raw()) }).unwrap();
    menus.insert(popup, 0, MenuItem { id: 100, state: 0, text: text("&New"), submenu: None }).unwrap();
    menus.insert(popup, 1, MenuItem { id: 0, state: MF_SEPARATOR, text: text(""), submenu: None }).unwrap();
    menus.insert(popup, 2, MenuItem { id: 102, state: 0, text: text("E&xit"), submenu: None }).unwrap();
    (menus, bar.raw(), popup.raw())
}

fn tracking(menus: &MenuManager, flags: u32, menu: u32) -> TrackLoop {
    let _ = menus;
    TrackLoop::new(flags | TPM_POPUPMENU, OWNER, menu, (0, 0))
}

fn message(message: u32, wparam: u64, lparam: i64) -> RetrievedMessage {
    RetrievedMessage { hwnd: OWNER as u64, message, wparam, lparam }
}

/// Every step to the end of tracking.
fn run(state: &mut TrackLoop, menus: &mut MenuManager) -> Vec<LoopStep> {
    let mut steps = Vec::new();
    loop { let step = state.next(menus); let done = matches!(step, LoopStep::Done(_)); steps.push(step); if done { return steps; } }
}

/// Every step up to the first one the caller is interested in.
fn drain(state: &mut TrackLoop, menus: &mut MenuManager, count: usize) -> Vec<LoopStep> {
    (0..count).map(|_| state.next(menus)).collect()
}

#[test]
fn entering_the_loop_notifies_the_owner_before_the_menu_is_shown() {
    let (mut menus, _, popup) = chain();
    let mut state = tracking(&menus, 0, popup);
    state.begin();
    let steps = drain(&mut state, &mut menus, 5);
    assert_eq!(steps, vec![
        LoopStep::Send(ProcCall { hwnd: OWNER as u64, message: WM_ENTERMENULOOP, wparam: 1, lparam: 0 }),
        LoopStep::Send(ProcCall { hwnd: OWNER as u64, message: WM_SETCURSOR, wparam: OWNER as u64, lparam: HTCAPTION }),
        LoopStep::Send(ProcCall { hwnd: OWNER as u64, message: WM_INITMENU, wparam: popup as u64, lparam: 0 }),
        LoopStep::Send(ProcCall { hwnd: OWNER as u64, message: WM_INITMENUPOPUP, wparam: popup as u64, lparam: 0 }),
        LoopStep::ShowTop,
    ]);
    // Nothing is queued: the loop wants a message.
    assert_eq!(state.next(&mut menus), LoopStep::NextMessage);
}

#[test]
fn a_silent_tracking_session_makes_no_owner_notification() {
    let (mut menus, _, popup) = chain();
    let mut state = tracking(&menus, TPM_NONOTIFY, popup);
    state.begin();
    assert_eq!(state.next(&mut menus), LoopStep::Send(ProcCall { hwnd: OWNER as u64, message: WM_SETCURSOR, wparam: OWNER as u64, lparam: HTCAPTION }));
    assert_eq!(state.next(&mut menus), LoopStep::ShowTop);
}

#[test]
fn a_key_that_moves_the_selection_repaints_and_tells_the_owner() {
    let (mut menus, _, popup) = chain();
    let mut state = tracking(&menus, 0, popup);
    assert!(state.message(&mut menus, message(WM_KEYDOWN, VK_DOWN as u64, 0), None));
    assert_eq!(menus.focused_item(MenuId::from_raw(popup).unwrap()), 0);
    assert_eq!(state.next(&mut menus), LoopStep::Effect(TrackEffect::Repaint { menu: popup }));
    let expected = 100 | ((MF_HILITE as u64) << 16);
    assert_eq!(state.next(&mut menus), LoopStep::Send(ProcCall { hwnd: OWNER as u64, message: WM_MENUSELECT, wparam: expected, lparam: popup as i64 }));
    assert_eq!(state.next(&mut menus), LoopStep::NextMessage);
    // The separator is skipped on the next step down.
    assert!(state.message(&mut menus, message(WM_KEYDOWN, VK_DOWN as u64, 0), None));
    assert_eq!(menus.focused_item(MenuId::from_raw(popup).unwrap()), 2);
}

#[test]
fn a_message_the_loop_does_not_consume_is_dispatched_to_its_own_window() {
    let (mut menus, _, popup) = chain();
    let mut state = tracking(&menus, 0, popup);
    let paint = RetrievedMessage { hwnd: 0x40, message: WM_PAINT, wparam: 0, lparam: 0 };
    assert!(state.message(&mut menus, paint, None));
    assert_eq!(state.next(&mut menus), LoopStep::Dispatch(ProcCall { hwnd: 0x40, message: WM_PAINT, wparam: 0, lparam: 0 }));
    assert_eq!(state.next(&mut menus), LoopStep::NextMessage);
    assert!(!state.tracker.exit);
}

#[test]
fn a_submenu_is_measured_only_after_its_owner_has_been_told_to_update_it() {
    let (mut menus, bar, popup) = chain();
    let mut state = TrackLoop::new(0, OWNER, bar, (0, 0));
    state.open_submenu(bar, 0, popup, true);
    assert_eq!(state.next(&mut menus), LoopStep::Send(ProcCall { hwnd: OWNER as u64, message: WM_INITMENUPOPUP, wparam: popup as u64, lparam: 0 }));
    // The owner's LRESULT is observed before the popup is measured.
    state.call_result(Ok(0x1234));
    assert_eq!(state.last_result(), Ok(0x1234));
    assert_eq!(state.next(&mut menus), LoopStep::ShowSub { menu: bar, position: 0, submenu: popup, select_first: true });
}

#[test]
fn a_silent_session_measures_the_submenu_without_notifying_the_owner() {
    let (mut menus, bar, popup) = chain();
    let mut state = TrackLoop::new(TPM_NONOTIFY, OWNER, bar, (0, 0));
    state.open_submenu(bar, 0, popup, false);
    assert_eq!(state.next(&mut menus), LoopStep::ShowSub { menu: bar, position: 0, submenu: popup, select_first: false });
}

#[test]
fn closing_popups_retires_each_window_and_notifies_the_owner_innermost_first() {
    let (mut menus, bar, popup) = chain();
    let mut state = TrackLoop::new(0, OWNER, bar, (0, 0));
    state.close_popups(&[bar, popup]);
    assert_eq!(drain(&mut state, &mut menus, 4), vec![
        LoopStep::Close { menu: bar },
        LoopStep::Send(ProcCall { hwnd: OWNER as u64, message: WM_UNINITMENUPOPUP, wparam: bar as u64, lparam: 0 }),
        LoopStep::Close { menu: popup },
        LoopStep::Send(ProcCall { hwnd: OWNER as u64, message: WM_UNINITMENUPOPUP, wparam: popup as u64, lparam: 0 }),
    ]);
}

#[test]
fn cancellation_unwinds_the_chain_and_leaves_the_loop() {
    let (mut menus, _, popup) = chain();
    let mut state = tracking(&menus, 0, popup);
    state.cancel();
    assert_eq!(drain(&mut state, &mut menus, 5), vec![
        LoopStep::Effect(TrackEffect::HideSubPopups { menu: popup }),
        LoopStep::Close { menu: popup },
        LoopStep::Send(ProcCall { hwnd: OWNER as u64, message: WM_UNINITMENUPOPUP, wparam: popup as u64, lparam: 0 }),
        LoopStep::Send(ProcCall { hwnd: OWNER as u64, message: WM_MENUSELECT, wparam: MENUSELECT_CLOSED, lparam: 0 }),
        LoopStep::Send(ProcCall { hwnd: OWNER as u64, message: WM_EXITMENULOOP, wparam: 1, lparam: 0 }),
    ]);
    assert_eq!(state.next(&mut menus), LoopStep::Done(1));
}

#[test]
fn a_posted_cancel_message_ends_the_loop_the_way_end_menu_asks() {
    let (mut menus, _, popup) = chain();
    let mut state = tracking(&menus, 0, popup);
    assert!(state.message(&mut menus, message(WM_CANCELMODE, 0, 0), None));
    assert!(state.tracker.exit);
}

#[test]
fn an_empty_popup_is_abandoned_before_the_chain_is_unwound() {
    let mut menus = MenuManager::new();
    let empty = menus.create_popup().unwrap().raw();
    let mut state = tracking(&menus, 0, empty);
    state.begin();
    state.abandon();
    assert_eq!(drain(&mut state, &mut menus, 3), vec![
        LoopStep::Send(ProcCall { hwnd: OWNER as u64, message: WM_EXITMENULOOP, wparam: 1, lparam: 0 }),
        LoopStep::Close { menu: empty },
        LoopStep::Send(ProcCall { hwnd: OWNER as u64, message: WM_UNINITMENUPOPUP, wparam: empty as u64, lparam: 0 }),
    ]);
    assert_eq!(state.next(&mut menus), LoopStep::Done(1));
}

#[test]
fn choosing_an_item_reports_its_command_when_the_caller_asked_for_one() {
    let (mut menus, _, popup) = chain();
    let mut state = tracking(&menus, TPM_RETURNCMD, popup);
    let id = MenuId::from_raw(popup).unwrap();
    menus.set_focused_item(id, 2).unwrap();
    let up = PointerEvent { pt: (5, 5), menu: Some(popup), hit: PopupHit::Item(2), menu_is_bar: false, right_button: false };
    assert!(state.message(&mut menus, message(WM_LBUTTONUP, 0, 0), Some(up)));
    assert!(state.tracker.exit);
    // Nothing is posted to the owner: the caller reads the command instead.
    let steps = run(&mut state, &mut menus);
    assert!(!steps.iter().any(|step| matches!(step, LoopStep::Effect(TrackEffect::Post { .. }))));
    assert_eq!(steps.last(), Some(&LoopStep::Done(102)));
}

#[test]
fn choosing_an_item_posts_its_command_when_the_caller_did_not() {
    let (mut menus, _, popup) = chain();
    let mut state = tracking(&menus, 0, popup);
    let id = MenuId::from_raw(popup).unwrap();
    menus.set_focused_item(id, 2).unwrap();
    let up = PointerEvent { pt: (5, 5), menu: Some(popup), hit: PopupHit::Item(2), menu_is_bar: false, right_button: false };
    assert!(state.message(&mut menus, message(WM_LBUTTONUP, 0, 0), Some(up)));
    assert_eq!(state.next(&mut menus), LoopStep::Effect(TrackEffect::Post { message: WM_COMMAND, wparam: 102, lparam: 0 }));
    assert_eq!(run(&mut state, &mut menus).last(), Some(&LoopStep::Done(1)));
}

#[test]
fn a_button_up_outside_a_tracked_popup_keeps_tracking_and_leaves_the_message() {
    let (mut menus, _, popup) = chain();
    let mut state = tracking(&menus, 0, popup);
    let outside = PointerEvent { pt: (900, 900), menu: None, hit: PopupHit::Nowhere, menu_is_bar: false, right_button: false };
    assert!(state.message(&mut menus, message(WM_LBUTTONUP, 0, 0), Some(outside)));
    assert!(!state.tracker.exit);
    assert_eq!(state.next(&mut menus), LoopStep::NextMessage);
}

#[test]
fn a_button_up_outside_a_tracked_menu_bar_ends_tracking_and_leaves_the_message() {
    let (mut menus, bar, _) = chain();
    let mut state = TrackLoop::new(0, OWNER, bar, (0, 0));
    let outside = PointerEvent { pt: (900, 900), menu: None, hit: PopupHit::Nowhere, menu_is_bar: false, right_button: false };
    // The reference leaves a message that ends tracking without being consumed
    // in the queue, so the application still sees the click.
    assert!(!state.message(&mut menus, message(WM_LBUTTONUP, 0, 0), Some(outside)));
    assert!(state.tracker.exit);
}

#[test]
fn an_empty_queue_tells_the_owner_the_menu_is_idle_once_before_waiting() {
    let (mut menus, _, popup) = chain();
    let mut state = tracking(&menus, 0, popup);
    state.set_current(popup, 0x88);
    assert!(!state.idle());
    assert_eq!(state.next(&mut menus), LoopStep::Send(ProcCall { hwnd: OWNER as u64, message: WM_ENTERIDLE, wparam: MSGF_MENU, lparam: 0x88 }));
    // Idle is reported once; the loop waits from then on.
    assert!(state.idle());
    assert_eq!(state.next(&mut menus), LoopStep::NextMessage);
    // Any message but a timer for another window re-arms it.
    let _ = state.message(&mut menus, RetrievedMessage { hwnd: 0x40, message: WM_PAINT, wparam: 0, lparam: 0 }, None);
    assert!(!state.idle());
}

#[test]
fn a_timer_for_another_window_does_not_re_arm_the_idle_notification() {
    let (mut menus, _, popup) = chain();
    let mut state = tracking(&menus, 0, popup);
    state.set_current(popup, 0x88);
    assert!(!state.idle());
    let _ = state.next(&mut menus);
    let _ = state.message(&mut menus, RetrievedMessage { hwnd: 0x40, message: WM_TIMER, wparam: 0, lparam: 0 }, None);
    assert!(state.idle());
}

#[test]
fn the_mouse_opening_a_submenu_queues_the_show_effect() {
    let (mut menus, bar, popup) = chain();
    let mut state = TrackLoop::new(0, OWNER, bar, (0, 0));
    let over = PointerEvent { pt: (4, 4), menu: Some(bar), hit: PopupHit::Item(0), menu_is_bar: true, right_button: false };
    assert!(state.message(&mut menus, message(WM_LBUTTONDOWN, 0, 0), Some(over)));
    let steps = drain(&mut state, &mut menus, 4);
    assert!(steps.contains(&LoopStep::Effect(TrackEffect::ShowSubPopup { menu: bar, select_first: false })));
    let _ = popup;
    assert!(menus.item(MenuId::from_raw(bar).unwrap(), 0, crate::win32_menu::MF_BYPOSITION).unwrap().state & MF_MOUSESELECT == 0);
}

/// A bar carrying File and Edit, each with a popup of its own.
fn bar_chain() -> (MenuManager, u32, u32, u32) {
    let mut menus = MenuManager::new();
    let bar = menus.create().unwrap();
    let file = menus.create_popup().unwrap();
    let edit = menus.create_popup().unwrap();
    menus.insert(bar, 0, MenuItem { id: 0, state: 0, text: text("&File"), submenu: Some(file.raw()) }).unwrap();
    menus.insert(bar, 1, MenuItem { id: 0, state: 0, text: text("&Edit"), submenu: Some(edit.raw()) }).unwrap();
    menus.insert(file, 0, MenuItem { id: 100, state: 0, text: text("&New"), submenu: None }).unwrap();
    menus.insert(edit, 0, MenuItem { id: 200, state: 0, text: text("&Copy"), submenu: None }).unwrap();
    (menus, bar.raw(), file.raw(), edit.raw())
}

/// One pointer event naming a bar item.
fn on_bar(bar: u32, hit: PopupHit) -> PointerEvent {
    PointerEvent { pt: (40, 4), menu: Some(bar), hit, menu_is_bar: true, right_button: false }
}

fn queued(state: &mut TrackLoop, menus: &mut MenuManager) -> Vec<LoopStep> {
    let mut steps = Vec::new();
    loop {
        let step = state.next(menus);
        let done = matches!(step, LoopStep::NextMessage | LoopStep::Done(_));
        steps.push(step);
        if done { return steps; }
    }
}

#[test]
fn a_press_entering_bar_tracking_is_applied_before_the_first_message() {
    let (mut menus, bar, _, _) = bar_chain();
    let mut state = TrackLoop::new(TPM_BUTTONDOWN | TPM_NONOTIFY, OWNER, bar, (40, 4));
    state.begin();
    assert_eq!(drain(&mut state, &mut menus, 3), vec![
        LoopStep::Send(ProcCall { hwnd: OWNER as u64, message: WM_SETCURSOR, wparam: OWNER as u64, lparam: HTCAPTION }),
        LoopStep::ShowTop,
        LoopStep::PressAt { point: (40, 4) },
    ]);
    state.press(&mut menus, &on_bar(bar, PopupHit::Item(1)));
    assert_eq!(menus.focused_item(MenuId::from_raw(bar).unwrap()), 1);
    let steps = queued(&mut state, &mut menus);
    assert!(steps.contains(&LoopStep::Effect(TrackEffect::ShowSubPopup { menu: bar, select_first: false })));
    assert_eq!(*steps.last().unwrap(), LoopStep::NextMessage);
}

#[test]
fn tracking_entered_without_a_press_takes_a_message_first() {
    let (mut menus, bar, _, _) = bar_chain();
    let mut state = TrackLoop::new(TPM_NONOTIFY, OWNER, bar, (0, 0));
    state.begin();
    assert_eq!(drain(&mut state, &mut menus, 2).last().unwrap(), &LoopStep::ShowTop);
    assert_eq!(state.next(&mut menus), LoopStep::NextMessage);
}

#[test]
fn a_press_naming_no_menu_ends_tracking_before_the_loop_runs() {
    let (mut menus, bar, _, _) = bar_chain();
    let mut state = TrackLoop::new(TPM_BUTTONDOWN | TPM_NONOTIFY, OWNER, bar, (40, 4));
    state.begin();
    let _ = drain(&mut state, &mut menus, 3);
    state.press(&mut menus, &PointerEvent { pt: (40, 4), menu: None, hit: PopupHit::Nowhere, menu_is_bar: false, right_button: false });
    assert!(matches!(queued(&mut state, &mut menus).last().unwrap(), LoopStep::Done(_)));
}

#[test]
fn moving_along_the_bar_closes_one_popup_and_opens_the_next() {
    let (mut menus, bar, _, _) = bar_chain();
    let mut state = TrackLoop::new(TPM_NONOTIFY, OWNER, bar, (0, 0));
    state.set_current(bar, 0);
    menus.set_focused_item(MenuId::from_raw(bar).unwrap(), 0).unwrap();
    state.message(&mut menus, message(WM_MOUSEMOVE, 0, 0), Some(on_bar(bar, PopupHit::Item(1))));
    let steps = queued(&mut state, &mut menus);
    assert_eq!(steps.iter().filter_map(|step| match step { LoopStep::Effect(effect) => Some(effect.clone()), _ => None }).collect::<Vec<_>>(),
        vec![TrackEffect::HideSubPopups { menu: bar }, TrackEffect::Repaint { menu: bar },
             TrackEffect::ShowSubPopup { menu: bar, select_first: false }]);
    assert_eq!(menus.focused_item(MenuId::from_raw(bar).unwrap()), 1);
}

#[test]
fn button_up_on_the_bar_item_that_opened_the_popup_keeps_it_open() {
    let (mut menus, bar, _, _) = bar_chain();
    let mut state = TrackLoop::new(TPM_NONOTIFY, OWNER, bar, (40, 4));
    state.set_current(bar, 0);
    menus.set_focused_item(MenuId::from_raw(bar).unwrap(), 0).unwrap();
    state.message(&mut menus, message(WM_LBUTTONUP, 0, 0), Some(on_bar(bar, PopupHit::Item(0))));
    assert_eq!(*queued(&mut state, &mut menus).last().unwrap(), LoopStep::NextMessage);
    // The second release on the same item is the one that closes the menu.
    state.message(&mut menus, message(WM_LBUTTONUP, 0, 0), Some(on_bar(bar, PopupHit::Item(0))));
    assert!(matches!(queued(&mut state, &mut menus).last().unwrap(), LoopStep::Done(_)));
}
