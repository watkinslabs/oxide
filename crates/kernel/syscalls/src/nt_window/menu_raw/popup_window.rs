//! The popup-menu window: a real window of the builtin popup-menu class that
//! shows one menu, and the effects the tracking loop applies to the chain of
//! them.
use super::entry::{current_tid, with_entry};
use super::raw::WM_UNINITMENUPOPUP;
use ipc::win32_menu::track::WM_MENUSELECT;
use super::session::MenuSession;
use alloc::vec::Vec;
use ipc::win32_menu::popup::{popup_origin, PopupLayout, PopupMetrics, TPM_NONOTIFY};
use ipc::win32_menu::track::{TrackEffect, MF_MOUSESELECT};
use ipc::win32_menu::{MenuId, MenuRect, MF_BYPOSITION};
use ipc::win32_window::{WindowId, WindowRect};

/// Registered name of the builtin popup-menu class.
pub(crate) const POPUP_MENU_CLASS: [u16; 6] = [b'#' as u16, b'3' as u16, b'2' as u16, b'7' as u16, b'6' as u16, b'8' as u16];
/// The popup-menu class stores its `HMENU` in the first window word.
pub(crate) const POPUP_MENU_EXTRA_OFFSET: i32 = 0;
const WS_POPUP: u32 = 0x8000_0000;

fn metrics() -> PopupMetrics {
    PopupMetrics { char_width: ipc::win32_gdi::MENU_CHAR_WIDTH, char_height: ipc::win32_gdi::MENU_CHAR_HEIGHT }
}

/// The rectangle a popup may occupy. # C: O(1)
pub(crate) fn work_area() -> MenuRect {
    let (width, height) = crate::nt_wine_window::metrics::screen_size(crate::nt_compositor::monitors_current).unwrap_or((0, 0));
    MenuRect { left: 0, top: 0, right: width, bottom: height }
}

/// Create the window one menu is shown in and retain the menu on it, the way
/// the reference creates a popup-menu-class window naming the menu as its
/// creation parameter. # C: O(N_classes + N_windows)
pub(crate) fn create_popup_window(owner: u64, menu: u32) -> Option<u64> {
    let tid = current_tid()?;
    let hwnd = with_entry(|entry| {
        let window = entry.state.create_class(tid, None, &POPUP_MENU_CLASS).ok()?;
        let _ = entry.state.set_window_long_ptr(window, POPUP_MENU_EXTRA_OFFSET, menu as u64);
        Some(window.raw() as u64)
    }).flatten()?;
    let _ = crate::nt_window::set_creation_metadata_current(hwnd, WS_POPUP, 0, owner, 0);
    Some(hwnd)
}

/// Measure, place and show one popup, returning its window. `xanchor` and
/// `yanchor` are the excluded item's size, which pushes a popup that will not
/// fit past the item rather than over it. # C: O(N_items + N_windows)
pub(crate) fn show_popup(session: &mut MenuSession, menu: u32, flags: u32, x: i32, y: i32, xanchor: i32, yanchor: i32) -> Option<u64> {
    let id = MenuId::from_raw(menu)?;
    let hwnd = match session.window_of(menu) { Some(hwnd) => hwnd, None => { let hwnd = create_popup_window(session.owner, menu)?; session.opened(menu, hwnd); hwnd } };
    let window = WindowId::from_raw(u32::try_from(hwnd).ok()?)?;
    let tid = current_tid()?;
    let Some(layout) = with_entry(|entry| {
        let _ = entry.menus.set_focused_item(id, ipc::win32_menu::popup::NO_SELECTED_ITEM);
        let max_height = { let mut info = ipc::win32_menu::MenuInfo::default(); let _ = entry.menus.info(id, ipc::win32_menu::MIM_MAXHEIGHT, &mut info); if info.max_height == 0 { i32::MAX } else { info.max_height as i32 } };
        entry.menus.popup_layout(id, metrics(), max_height).ok()
    }).flatten() else { return None; };
    let (x, y) = popup_origin(flags, x, y, layout.width, layout.height, work_area(), xanchor, yanchor);
    with_entry(|entry| {
        let _ = entry.state.set_rect(window, WindowRect { left: x, top: y, right: x + layout.width, bottom: y + layout.height });
        let _ = entry.state.show(tid, window, true);
        let _ = entry.state.invalidate(window, None);
    });
    Some(hwnd)
}

/// The layout of one open popup, for hit testing against its window.
/// # C: O(N_items)
pub(crate) fn layout_of(menu: u32) -> Option<PopupLayout> {
    let id = MenuId::from_raw(menu)?;
    with_entry(|entry| entry.menus.popup_layout(id, metrics(), i32::MAX).ok()).flatten()
}

/// Screen rectangle of one open popup window. # C: O(N_windows)
pub(crate) fn window_rect(hwnd: u64) -> Option<MenuRect> {
    let window = WindowId::from_raw(u32::try_from(hwnd).ok()?)?;
    let rect = with_entry(|entry| entry.state.rect(window)).flatten()?;
    Some(MenuRect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom })
}

/// Retire the window showing one menu and tell the owner the popup is done
/// with, as the reference does when it takes a submenu down. # C: O(N_windows)
pub(crate) fn hide_popup(session: &mut MenuSession, menu: u32, flags: u32) {
    let Some(hwnd) = session.closed(menu) else { return; };
    if let Some(window) = u32::try_from(hwnd).ok().and_then(WindowId::from_raw) {
        with_entry(|entry| { let _ = entry.state.destroy(window); });
    }
    if flags & TPM_NONOTIFY == 0 {
        let _ = crate::nt_window::send::send_for_current(session.owner, WM_UNINITMENUPOPUP, menu as u64, 0);
    }
}

/// Close the submenu open under one menu's focused item, innermost first, the
/// way the reference unwinds a chain of popups. # C: O(N_open * N_items)
pub(crate) fn hide_sub_popups(session: &mut MenuSession, menu: u32, flags: u32) {
    let Some(id) = MenuId::from_raw(menu) else { return; };
    let Some(submenu) = with_entry(|entry| {
        let focused = entry.menus.focused_item(id);
        if focused == ipc::win32_menu::popup::NO_SELECTED_ITEM { return None; }
        let item = entry.menus.item(id, focused, MF_BYPOSITION).ok()?;
        if item.state & MF_MOUSESELECT == 0 { return None; }
        let submenu = item.submenu?;
        if let Ok(item) = entry.menus.item_mut_by_position(id, focused as usize) { item.state &= !MF_MOUSESELECT; }
        Some(submenu)
    }).flatten() else { return; };
    hide_sub_popups(session, submenu, flags);
    if let Some(submenu_id) = MenuId::from_raw(submenu) {
        with_entry(|entry| { let _ = entry.menus.set_focused_item(submenu_id, ipc::win32_menu::popup::NO_SELECTED_ITEM); });
    }
    hide_popup(session, submenu, flags);
}

/// Open the submenu of one menu's focused item beside the item, and report the
/// menu tracking now follows. # C: O(N_items + N_windows)
pub(crate) fn show_sub_popup(session: &mut MenuSession, menu: u32, _select_first: bool, flags: u32) -> u32 {
    let Some(id) = MenuId::from_raw(menu) else { return menu; };
    let Some(hwnd) = session.window_of(menu) else { return menu; };
    let Some((focused, submenu)) = with_entry(|entry| {
        let focused = entry.menus.focused_item(id);
        if focused == ipc::win32_menu::popup::NO_SELECTED_ITEM { return None; }
        let submenu = entry.menus.item(id, focused, MF_BYPOSITION).ok()?.submenu?;
        Some((focused, submenu))
    }).flatten() else { return menu; };
    hide_sub_popups(session, menu, flags);
    let (Some(rect), Some(layout)) = (window_rect(hwnd), layout_of(menu)) else { return menu; };
    let Some(item_rect) = layout.items.get(focused as usize).copied() else { return menu; };
    if flags & TPM_NONOTIFY == 0 {
        let _ = crate::nt_window::send::send_for_current(session.owner, super::raw::WM_INITMENUPOPUP, submenu as u64, focused as u64);
    }
    with_entry(|entry| { if let Ok(item) = entry.menus.item_mut_by_position(id, focused as usize) { item.state |= MF_MOUSESELECT; } });
    // A submenu opens at the item's right edge, and never inherits the
    // caller's alignment.
    let x = rect.left + item_rect.right;
    let y = rect.top + item_rect.top;
    let plain = flags & !(ipc::win32_menu::popup::TPM_CENTERALIGN | ipc::win32_menu::popup::TPM_RIGHTALIGN
        | ipc::win32_menu::popup::TPM_VCENTERALIGN | ipc::win32_menu::popup::TPM_BOTTOMALIGN);
    if show_popup(session, submenu, plain, x, y, item_rect.right - item_rect.left, item_rect.bottom - item_rect.top).is_none() { return menu; }
    submenu
}

/// The warning a menu makes when a typed key names no item. It is silent
/// while the beep setting is off. # C: O(1)
fn beep() {
    const BEEP_HZ: u32 = 750;
    const BEEP_MS: u32 = 125;
    if crate::nt_window::USER_SETTINGS.lock().beep_enabled() { let _ = sound::beep::beep(BEEP_HZ, BEEP_MS); }
}

/// Highlight the first item a freshly opened submenu can select, the way the
/// reference moves the selection into a keyboard-opened popup. # C: O(N_items)
fn select_first_item(session: &mut MenuSession, menu: u32) {
    let Some(id) = MenuId::from_raw(menu) else { return; };
    let position = with_entry(|entry| {
        let count = entry.menus.count(id).unwrap_or(0);
        (0..count).find(|position| entry.menus.item(id, *position as u32, MF_BYPOSITION)
            .is_ok_and(|item| item.state & ipc::win32_menu::MF_SEPARATOR == 0))
    }).flatten();
    let Some(position) = position else { return; };
    with_entry(|entry| { let _ = entry.menus.set_focused_item(id, position as u32); });
    if let Some(window) = session.window_of(menu).and_then(|hwnd| u32::try_from(hwnd).ok()).and_then(ipc::win32_window::WindowId::from_raw) {
        with_entry(|entry| { let _ = entry.state.invalidate(window, None); });
    }
}

/// Apply one batch of tracking decisions to the live windows, reporting the
/// menu tracking follows after any submenu it opened. # C: O(N_effects * N_windows)
pub(crate) fn apply(session: &mut MenuSession, effects: Vec<TrackEffect>, flags: u32, current: u32) -> u32 {
    let mut current = current;
    for effect in effects {
        match effect {
            TrackEffect::Repaint { menu } => {
                if let Some(window) = session.window_of(menu).and_then(|hwnd| u32::try_from(hwnd).ok()).and_then(WindowId::from_raw) {
                    with_entry(|entry| { let _ = entry.state.invalidate(window, None); });
                } else { let _ = crate::nt_window::draw_menu_bar_for_current(session.owner); }
            }
            TrackEffect::MenuSelect { wparam, lparam } => { let _ = crate::nt_window::send::send_for_current(session.owner, WM_MENUSELECT, wparam, lparam as u64); }
            TrackEffect::HideSubPopups { menu } => hide_sub_popups(session, menu, flags),
            TrackEffect::ShowSubPopup { menu, select_first } => {
                current = show_sub_popup(session, menu, select_first, flags);
                if select_first && current != menu { select_first_item(session, current); }
            }
            TrackEffect::Post { message, wparam, lparam } => {
                let _ = crate::nt_window::dispatch(syscall::nt::NtCall { service: syscall::nt::NtService::PostMessage,
                    args: syscall::SyscallArgs { a0: session.owner, a1: message as u64, a2: wparam, a3: lparam as u64, a4: 0, a5: 0 } });
            }
            TrackEffect::Beep => beep(),
        }
    }
    current
}
