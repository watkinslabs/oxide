//! The modal menu-tracking loop: it shows the popup, consumes the thread's
//! queue until an item is chosen or tracking is cancelled, and reports the
//! chosen command.
use super::entry::{current_tid, with_entry};
use super::popup_window::{self, layout_of, window_rect};
use super::raw::*;
use super::session::{self, LoopAction, MenuSession};
use alloc::sync::Arc;
use alloc::vec::Vec;
use ipc::win32_menu::popup::{hit_test, PopupHit, NO_SELECTED_ITEM, TF_ENDMENU, TPM_POPUPMENU, TPM_RETURNCMD};
use ipc::win32_menu::track::{PointerEvent, TrackEffect, Tracker, EXEC_NOTHING, EXEC_POPUP_SHOWN, ITEM_NEXT, ITEM_PREV};
use ipc::win32_menu::MenuId;
use ipc::win32_window::{MessageFilter, WindowId};

const WM_ENTERMENULOOP: u32 = 0x0211;
const WM_EXITMENULOOP: u32 = 0x0212;
const WM_INITMENU: u32 = 0x0116;
const WM_SETCURSOR: u32 = 0x0020;
const HTCAPTION: u64 = 2;
/// Every message of every window of the calling thread.
const ANY_MESSAGE: MessageFilter = MessageFilter { hwnd: None, first: 0, last: 0 };
/// Capture claimed for menu tracking rather than an application drag.
const CAPTURE_MENU: u32 = ipc::win32_window::CAPTURE_MENU;

/// Enter menu tracking for one window: the owner learns the loop has begun and
/// gets its chance to update the menu before it is shown. # C: O(N_windows); # Sleeps: yes
pub(crate) fn init_tracking(owner: u64, menu: u32, is_popup: bool, flags: u32) {
    if flags & TPM_NONOTIFY == 0 { let _ = crate::nt_window::send::send_for_current(owner, WM_ENTERMENULOOP, is_popup as u64, 0); }
    let _ = crate::nt_window::send::send_for_current(owner, WM_SETCURSOR, owner, HTCAPTION);
    if flags & TPM_NONOTIFY == 0 { let _ = crate::nt_window::send::send_for_current(owner, WM_INITMENU, menu as u64, 0); }
}

/// Leave menu tracking. # C: O(1); # Sleeps: yes
pub(crate) fn exit_tracking(owner: u64, is_popup: bool) {
    let _ = crate::nt_window::send::send_for_current(owner, WM_EXITMENULOOP, is_popup as u64, 0);
}

/// Claim or release the capture the tracked menu holds. # C: O(N_windows)
fn set_capture(hwnd: Option<u64>) {
    let Some(tid) = current_tid() else { return; };
    let window = hwnd.and_then(|hwnd| u32::try_from(hwnd).ok()).and_then(WindowId::from_raw);
    with_entry(|entry| { let _ = entry.state.set_capture_window(tid, window, CAPTURE_MENU); });
}

/// Which menu of the tracked chain a screen point falls on, and where in it.
/// The innermost popup wins, as the reference walks the chain from the open
/// submenu outwards. # C: O(N_open * N_items)
fn menu_from_point(session: &MenuSession, point: (i32, i32)) -> (Option<u32>, PopupHit) {
    for (menu, hwnd) in session.innermost_first() {
        let (Some(rect), Some(layout)) = (window_rect(hwnd), layout_of(menu)) else { continue; };
        let hit = hit_test(&layout, rect, point);
        if hit != PopupHit::Nowhere { return (Some(menu), hit); }
    }
    (None, PopupHit::Nowhere)
}

/// Take the next message the loop must act on, waiting for one when the queue
/// is empty. Absent means the thread is gone. # C: O(N_queued); # Sleeps: yes
fn next_message(owner: u64) -> Option<(u32, u64, i64)> {
    let tid = current_tid()?;
    loop {
        let taken = with_entry(|entry| {
            entry.state.expire_timers(timekeeper::monotonic_ns());
            let message = entry.state.peek_for_thread(tid, ANY_MESSAGE, true);
            (message, Arc::clone(&entry.wait))
        })?;
        let (message, wait) = taken;
        if let Some(message) = message { return Some((message.message, message.wparam, message.lparam)); }
        let group = Arc::clone(&sched::live::current()?.thread_group);
        // SAFETY: the menu loop holds an owned wait-list reference and rechecks
        // the canonical queue after every wake, without holding the GUI lock.
        let outcome = unsafe { sched::live::wait_event_interruptible(&wait, || {
            let mut entries = crate::nt_window::GUI.lock();
            entries.retain(|entry| entry.group.upgrade().is_some());
            entries.iter_mut().find(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
                .is_some_and(|entry| entry.state.peek_for_thread(tid, ANY_MESSAGE, false).is_some())
        }) };
        if outcome != sched::task::WaitOutcome::Ready { let _ = owner; return None; }
    }
}

/// Whether the session was told to stop. # C: O(N_process_gui_states)
fn cancelled() -> bool { with_entry(|entry| entry.menu_tracking.as_ref().is_some_and(|tracking| tracking.exit)).unwrap_or(true) }

/// Run the modal loop over one menu chain and report the chosen command: an
/// item id, zero when tracking ended without one, and the no-command report
/// while the loop is still deciding. # C: O(N_messages * N_items); # Sleeps: yes
pub(crate) fn track_menu(session: &mut MenuSession, menu: u32, flags: u32, point: (i32, i32)) -> i32 {
    let mut tracker = Tracker::new(flags, session.owner as u32, menu, point);
    let mut executed = EXEC_NOTHING;
    let capture = if flags & TPM_POPUPMENU != 0 { session.window_of(menu).unwrap_or(session.owner) } else { session.owner };
    set_capture(Some(capture));
    if flags & TF_ENDMENU != 0 { tracker.exit = true; }
    if flags & TPM_POPUPMENU != 0 && MenuId::from_raw(menu).and_then(|id| with_entry(|entry| entry.menus.count(id).unwrap_or(0))).unwrap_or(0) == 0 {
        tracker.exit = true;
    }
    while !tracker.exit && !cancelled() {
        let Some((message, wparam, lparam)) = next_message(session.owner) else { break; };
        let mut effects: Vec<TrackEffect> = Vec::new();
        match session::classify(message, wparam, lparam) {
            LoopAction::Cancel => { tracker.exit = true; }
            LoopAction::ButtonDown { point, right } => {
                let event = pointer_event(session, point, right);
                if !with_menus_mut(|menus| tracker.button_down(menus, &event, &mut effects)) { tracker.exit = true; }
            }
            LoopAction::ButtonUp { point, right } => {
                let event = pointer_event(session, point, right);
                if event.menu.is_some() {
                    let chosen = with_menus_mut(|menus| tracker.button_up(menus, &event, &mut effects));
                    if chosen != EXEC_NOTHING { executed = chosen; tracker.exit = true; }
                } else if flags & TPM_POPUPMENU == 0 { tracker.exit = true; }
            }
            LoopAction::Move { point } => {
                let event = pointer_event(session, point, false);
                with_menus_mut(|menus| { tracker.mouse_move(menus, &event, &mut effects); });
            }
            LoopAction::Key { vk } => key_down(&mut tracker, vk, &mut effects, &mut executed),
            LoopAction::Char { ch } => {
                let chosen = with_menus_mut(|menus| tracker.char_key(menus, ch, &mut effects));
                if tracker.exit && chosen != EXEC_POPUP_SHOWN { executed = chosen; }
            }
            LoopAction::Pointer | LoopAction::Other => {}
        }
        tracker.current_menu = popup_window::apply(session, effects, flags, tracker.current_menu);
    }
    set_capture(None);
    let top = tracker.top_menu;
    popup_window::hide_sub_popups(session, top, flags);
    let mut effects = Vec::new();
    with_menus_mut(|menus| tracker.select_item(menus, &mut effects, top, NO_SELECTED_ITEM, false, 0));
    let _ = popup_window::apply(session, effects, flags, tracker.current_menu);
    let _ = crate::nt_window::send::send_for_current(session.owner, ipc::win32_menu::track::WM_MENUSELECT, 0xffff_0000, 0);
    if flags & TPM_RETURNCMD == 0 { return 1; }
    if executed == EXEC_NOTHING { 0 } else { executed }
}

/// One pointer event resolved against the open chain. # C: O(N_open * N_items)
fn pointer_event(session: &MenuSession, point: (i32, i32), right: bool) -> PointerEvent {
    let (menu, hit) = menu_from_point(session, point);
    let menu_is_bar = menu.and_then(MenuId::from_raw).and_then(|id| with_entry(|entry| entry.menus.is_popup(id).unwrap_or(true))).is_some_and(|popup| !popup);
    PointerEvent { pt: point, menu, hit, menu_is_bar, right_button: right }
}

/// Virtual keys the tracking loop acts on itself. # C: O(N_items)
fn key_down(tracker: &mut Tracker, vk: u32, effects: &mut Vec<TrackEffect>, executed: &mut i32) {
    let current = tracker.current_menu;
    match vk {
        session::VK_MENU | session::VK_F10 | session::VK_ESCAPE => tracker.exit = true,
        session::VK_HOME | session::VK_END => with_menus_mut(|menus| {
            tracker.select_item(menus, effects, current, NO_SELECTED_ITEM, false, 0);
            tracker.move_selection(menus, effects, current, if vk == session::VK_HOME { ITEM_NEXT } else { ITEM_PREV });
        }),
        session::VK_UP | session::VK_DOWN => with_menus_mut(|menus| {
            let popup = MenuId::from_raw(current).and_then(|id| menus.is_popup(id).ok()).unwrap_or(false);
            if popup { tracker.move_selection(menus, effects, current, if vk == session::VK_UP { ITEM_PREV } else { ITEM_NEXT }); }
            else { effects.push(TrackEffect::ShowSubPopup { menu: current, select_first: true }); }
        }),
        session::VK_LEFT => with_menus_mut(|menus| tracker.move_selection(menus, effects, tracker.top_menu, ITEM_PREV)),
        session::VK_RIGHT => with_menus_mut(|menus| {
            let has_submenu = MenuId::from_raw(current).map(|id| { let focused = menus.focused_item(id); focused != NO_SELECTED_ITEM && menus.is_submenu_item(id, focused) }).unwrap_or(false);
            if has_submenu { effects.push(TrackEffect::ShowSubPopup { menu: current, select_first: true }); }
            else { tracker.move_selection(menus, effects, tracker.top_menu, ITEM_NEXT); }
        }),
        _ => { let _ = executed; }
    }
}

/// Run one decision against the canonical menu owner. # C: O(N_process_gui_states)
fn with_menus_mut<R: Default>(f: impl FnOnce(&mut ipc::win32_menu::MenuManager) -> R) -> R {
    with_entry(|entry| f(&mut entry.menus)).unwrap_or_default()
}

/// Where a popup opens for `TrackPopupMenuEx`, and the loop that follows it.
/// Reports the chosen command, or zero when nothing was chosen.
/// # C: O(N_messages * N_items); # Sleeps: yes
pub(crate) fn track_popup_menu(owner: u64, menu: u32, flags: u32, x: i32, y: i32) -> i32 {
    let mut session = MenuSession::new(owner);
    init_tracking(owner, menu, true, flags);
    if flags & TPM_NONOTIFY == 0 { let _ = crate::nt_window::send::send_for_current(owner, WM_INITMENUPOPUP, menu as u64, 0); }
    let shown = popup_window::show_popup(&mut session, menu, flags, x, y, 0, 0).is_some();
    let chosen = if shown { track_menu(&mut session, menu, flags | TPM_POPUPMENU, (x, y)) } else { 0 };
    popup_window::hide_popup(&mut session, menu, flags);
    exit_tracking(owner, true);
    chosen
}
