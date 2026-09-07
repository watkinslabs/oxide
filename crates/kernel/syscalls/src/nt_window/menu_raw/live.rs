//! Live routing for the system menu, whole-menu properties, the default and
//! highlighted items, hit testing, tracking and cancellation.
use super::raw::*;
use super::entry::with_entry;

use ipc::win32_menu::{MenuId, MenuRect, MENUINFO_BYTES, MF_BYPOSITION, MF_POPUP, MF_SYSMENU, NO_DEFAULT_ITEM};
use ipc::win32_window::WindowId;

/// Route one menu ordinal. # C: O(1) plus the arm's own cost; # Sleeps: yes
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    let arg = |index: usize| args.get(index).copied().unwrap_or(0);
    match ordinal {
        END_MENU => Some(end_menu()),
        GET_SYSTEM_MENU => Some(get_system_menu(arg(0), arg(1) != 0)),
        SET_SYSTEM_MENU => Some(set_system_menu(arg(0), arg(1))),
        HILITE_MENU_ITEM => Some(hilite_menu_item(arg(0), arg(1), arg(2) as u32, arg(3) as u32)),
        MENU_ITEM_FROM_POINT => Some(menu_item_from_point(arg(0), arg(1), arg(2) as i32, arg(3) as i32)),
        SET_MENU_CONTEXT_HELP_ID => Some(set_context_help_id(arg(0), arg(1) as u32)),
        SET_MENU_DEFAULT_ITEM => Some(set_default_item(arg(0), arg(1) as u32, arg(2) != 0)),
        THUNKED_MENU_INFO => Some(thunked_menu_info(arg(0), arg(1))),
        TRACK_POPUP_MENU_EX => Some(track_popup_at(arg(0), arg(1) as u32, arg(2) as i32, arg(3) as i32, arg(4))),
        _ => None,
    }
}

fn menu_of(raw: u64) -> Option<MenuId> { u32::try_from(raw).ok().and_then(MenuId::from_raw) }
fn window_of(raw: u64) -> Option<WindowId> { u32::try_from(raw).ok().and_then(WindowId::from_raw) }

/// Cancel any menu this thread is tracking, telling the tracking window to
/// leave its modal loop. # C: O(N_windows); # Sleeps: yes
fn end_menu() -> u64 {
    // The loop owns the session and unwinds it; cancellation only raises the
    // flag and wakes the loop with a message it always consumes.
    let Some(owner) = with_entry(|entry| {
        let tracking = entry.menu_tracking.as_mut()?;
        if tracking.exit { return None; }
        tracking.exit = true;
        Some(tracking.owner)
    }).flatten() else { return 0; };
    // The loop takes every message of its own thread, so waking it through
    // the owner window reaches it as surely as through the popup.
    let _ = crate::nt_window::dispatch(syscall::nt::NtCall { service: syscall::nt::NtService::PostMessage,
        args: syscall::SyscallArgs { a0: owner, a1: WM_CANCELMODE as u64, a2: 0, a3: 0, a4: 0, a5: 0 } });
    1
}

/// Build one window's system menu: a bar carrying a single popup item, whose
/// submenu holds the standard window commands. # C: O(N_menus)
fn build_system_menu(window: WindowId, popup: Option<MenuId>) -> Option<MenuId> {
    with_entry(|entry| {
        let bar = entry.menus.create().ok()?;
        let popup = match popup {
            Some(existing) => existing,
            None => {
                let created = entry.menus.create_popup().ok()?;
                entry.menus.fill_system_menu(created, &SYSTEM_MENU_COMMANDS).ok()?;
                let _ = entry.menus.set_default_item(created, SC_CLOSE, false);
                created
            }
        };
        entry.menus.insert(bar, 0, ipc::win32_menu::MenuItem { id: popup.raw(), state: MF_SYSMENU | MF_POPUP,
            text: alloc::vec::Vec::new(), submenu: Some(popup.raw()) }).ok()?;
        let _ = entry.state.set_sys_menu(window, Some(bar.raw()));
        Some(popup)
    }).flatten()
}

/// Report the window's system-menu popup, building one on first use. A revert
/// request discards the existing menu and reports none. # C: O(N_menus)
fn get_system_menu(hwnd: u64, revert: bool) -> u64 {
    let Some(window) = window_of(hwnd) else { return 0; };
    let existing = with_entry(|entry| {
        let record = entry.state.get(window)?;
        Some((record.style, record.sys_menu))
    }).flatten();
    let Some((style, stored)) = existing else { return 0; };
    if revert {
        if let Some(bar) = stored.and_then(MenuId::from_raw) {
            let _ = with_entry(|entry| { let _ = entry.menus.destroy(bar); let _ = entry.state.set_sys_menu(window, None); });
        }
        return system_menu_result(true, 0);
    }
    let bar = match stored.and_then(MenuId::from_raw) {
        Some(bar) => bar,
        None => {
            if !has_system_menu(style) { return 0; }
            let Some(popup) = build_system_menu(window, None) else { return 0; };
            return system_menu_result(false, popup.raw() as u64);
        }
    };
    let popup = with_entry(|entry| entry.menus.item(bar, 0, MF_BYPOSITION).ok().and_then(|item| item.submenu)).flatten();
    system_menu_result(false, popup.unwrap_or(0) as u64)
}

/// Replace the window's system menu with the caller's popup. # C: O(N_menus)
fn set_system_menu(hwnd: u64, raw: u64) -> u64 {
    let Some(window) = window_of(hwnd) else { return 0; };
    let Some(popup) = menu_of(raw) else { return 0; };
    let stored = with_entry(|entry| entry.state.sys_menu(window)).flatten();
    if let Some(bar) = stored.and_then(MenuId::from_raw) { let _ = with_entry(|entry| entry.menus.destroy(bar)); }
    build_system_menu(window, Some(popup)).is_some() as u64
}

/// Move the highlight within one menu and repaint the bar when it moves.
/// # C: O(N_items); # Sleeps: yes
fn hilite_menu_item(hwnd: u64, raw: u64, item: u32, hilite: u32) -> u64 {
    let Some(menu) = menu_of(raw) else { return 0; };
    let by_position = hilite & MF_BYPOSITION != 0;
    let moved = with_entry(|entry| {
        let position = entry.menus.position(menu, item, if by_position { MF_BYPOSITION } else { 0 }).ok()?;
        entry.menus.hilite(menu, position, hilite & MF_HILITE_REQUEST != 0).ok()
    }).flatten();
    let Some(moved) = moved else { return 0; };
    if moved { let _ = crate::nt_window::draw_menu_bar_for_current(hwnd); }
    1
}

/// `MF_HILITE`, the bit that asks for the highlight rather than removing it.
const MF_HILITE_REQUEST: u32 = 0x0000_0080;

/// The bar item under a point, or the absent-item report. # C: O(N_items)
fn menu_item_from_point(hwnd: u64, raw: u64, x: i32, y: i32) -> u64 {
    const NO_ITEM: u64 = u64::MAX;
    let Some(menu) = menu_of(raw) else { return NO_ITEM; };
    let Some(window) = window_of(hwnd) else { return NO_ITEM; };
    let found = with_entry(|entry| {
        let rect = entry.state.rect(window)?;
        let origin = MenuRect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom };
        let cells = ipc::win32_gdi::menu_bar_metrics();
        entry.menus.item_from_point(menu, (x, y), origin, cells.char_width, cells.char_height, cells.bar_height).ok()?
    }).flatten();
    found.map_or(NO_ITEM, |position| position as u64)
}

fn set_context_help_id(raw: u64, id: u32) -> u64 {
    let Some(menu) = menu_of(raw) else { return 0; };
    with_entry(|entry| entry.menus.set_context_help_id(menu, id).is_ok()).unwrap_or(false) as u64
}

fn set_default_item(raw: u64, item: u32, by_position: bool) -> u64 {
    let Some(menu) = menu_of(raw) else { return 0; };
    let item = if item == u32::MAX { NO_DEFAULT_ITEM } else { item };
    with_entry(|entry| entry.menus.set_default_item(menu, item, by_position).unwrap_or(false)).unwrap_or(false) as u64
}

/// Store the whole-menu properties the caller's record names. # C: O(N_menus)
fn thunked_menu_info(raw: u64, record: u64) -> u64 {
    if record == 0 { crate::nt_rtl::set_last_win32_error(ERROR_NOACCESS as u64); return 0; }
    let mut bytes = [0u8; MENUINFO_BYTES as usize];
    if uaccess::copy_from_user(&mut bytes, record).is_err() { crate::nt_rtl::set_last_win32_error(ERROR_NOACCESS as u64); return 0; }
    let Some((mask, info)) = decode_menu_info(bytes) else { crate::nt_rtl::set_last_win32_error(ERROR_INVALID_MENU_HANDLE as u64); return 0; };
    let Some(menu) = menu_of(raw) else { crate::nt_rtl::set_last_win32_error(ERROR_INVALID_MENU_HANDLE as u64); return 0; };
    let stored = with_entry(|entry| entry.menus.set_info(menu, mask, info).is_ok()).unwrap_or(false);
    if !stored { crate::nt_rtl::set_last_win32_error(ERROR_INVALID_MENU_HANDLE as u64); return 0; }
    1
}

/// Read the whole-menu properties one caller's mask names, leaving every
/// other field of its record as it supplied it. A valid handle is what
/// `IsMenu` is: the client asks for an empty mask and reads only the answer,
/// and the resource menu loader will not attach a submenu to an item until it
/// has. # C: O(N_menus) plus bounded usercopy
pub(crate) fn get_menu_info(raw: u64, record: u64) -> u64 {
    if record == 0 { crate::nt_rtl::set_last_win32_error(ERROR_INVALID_PARAMETER as u64); return 0; }
    let mut bytes = [0u8; MENUINFO_BYTES as usize];
    if uaccess::copy_from_user(&mut bytes, record).is_err() { crate::nt_rtl::set_last_win32_error(ERROR_INVALID_PARAMETER as u64); return 0; }
    let Some((mask, mut info)) = decode_menu_info(bytes) else { crate::nt_rtl::set_last_win32_error(ERROR_INVALID_PARAMETER as u64); return 0; };
    let Some(menu) = menu_of(raw) else { crate::nt_rtl::set_last_win32_error(ERROR_INVALID_PARAMETER as u64); return 0; };
    let read = with_entry(|entry| entry.menus.info(menu, mask, &mut info).is_ok()).unwrap_or(false);
    if !read { crate::nt_rtl::set_last_win32_error(ERROR_INVALID_PARAMETER as u64); return 0; }
    if uaccess::copy_to_user(record, &encode_menu_info(bytes, info)).is_err() { crate::nt_rtl::set_last_win32_error(ERROR_INVALID_PARAMETER as u64); return 0; }
    1
}

/// Show one popup for a window and run the modal loop that chooses a command
/// from it. The chosen command is reported when the caller asked for it, and
/// posted to the owner otherwise. # C: O(N_messages * N_items); # Sleeps: yes
fn track_popup_at(raw: u64, flags: u32, x: i32, y: i32, hwnd: u64) -> u64 {
    let Some(menu) = menu_of(raw) else { crate::nt_rtl::set_last_win32_error(ERROR_INVALID_MENU_HANDLE as u64); return 0; };
    let known = with_entry(|entry| entry.menus.contains(menu)).unwrap_or(false);
    if !known { crate::nt_rtl::set_last_win32_error(ERROR_INVALID_MENU_HANDLE as u64); return 0; }
    let Some(_) = window_of(hwnd) else { crate::nt_rtl::set_last_win32_error(ERROR_INVALID_WINDOW_HANDLE as u64); return 0; };
    let already = with_entry(|entry| entry.menu_tracking.is_some()).unwrap_or(false);
    if already { crate::nt_rtl::set_last_win32_error(ERROR_POPUP_ALREADY_ACTIVE as u64); return 0; }
    let _ = with_entry(|entry| entry.menu_tracking = Some(super::session::MenuCancel { owner: hwnd, exit: false }));
    // The loop suspends in every window procedure it enters, so it reports the
    // chosen command from the callback return that finishes it, not from here.
    super::track_live::track_popup_menu(hwnd, menu.raw(), flags, x, y)
}
