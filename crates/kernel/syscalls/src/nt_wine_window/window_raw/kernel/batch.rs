//! Deferred window-position ordinals.
use super::*;
use ipc::win32_window::DeferredPosition;
use crate::nt_window as owner;

/// # C: O(window owner work)
pub(super) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    Some(match ordinal {
        BEGIN_DEFER_WINDOW_POS => owner::begin_defer_for_current(args[0] as u32 as i32).unwrap_or(0) as u64,
        DEFER_WINDOW_POS_AND_BAND => defer(args),
        END_DEFER_WINDOW_POS_EX => end(args[0]),
        ARRANGE_ICONIC_WINDOWS => owner::iconic_children_for_current(args[0]).len() as u64,
        SHOW_OWNED_POPUPS => show_owned_popups(args[0], args[1] != 0),
        SHOW_WINDOW_ASYNC => crate::nt_wine_window::placement::show(args[0], args[1]),
        GET_INTERNAL_WINDOW_POS => internal_window_pos(args[0], args[1], args[2]),
        SET_INTERNAL_WINDOW_POS => set_internal_window_pos(args),
        GET_WINDOW_DC => crate::nt_gdi::get_dc_ex_for_current(args[0] as u32, 0, DCX_WINDOW_DC),
        PRINT_WINDOW => print_window(args[0], args[1], args[2] as u32),
        _ => return None,
    })
}

/// A window device context covers the whole window and uses the class and
/// window styles to decide its clipping.
const DCX_WINDOW_DC: u32 = 0x0000_0001 | 0x0001_0000;

fn defer(args: &[u64]) -> u64 {
    let (Some(cy), Some(flags)) = (crate::nt_dispatch::stack_argument(6), crate::nt_dispatch::stack_argument(7))
        else { return 0; };
    let Ok(handle) = u32::try_from(args[0]) else { return 0; };
    let Some(window) = args[1].try_into().ok().and_then(ipc::win32_window::WindowId::from_raw) else { return 0; };
    if !owner::window_is_live(args[1]) { return 0; }
    let position = DeferredPosition { window, insert_after: args[2], x: args[3] as u32 as i32,
        y: args[4] as u32 as i32, cx: args[5] as u32 as i32, cy: cy as u32 as i32, flags: flags as u32 };
    if owner::defer_for_current(handle, position).is_err() { return 0; }
    args[0]
}

/// Ending a batch replays every move through the canonical position owner.
/// # C: O(N_entries * position owner work)
fn end(handle: u64) -> u64 {
    let Ok(handle) = u32::try_from(handle) else { return win_bool(false); };
    let Ok(moves) = owner::end_defer_for_current(handle) else { return win_bool(false); };
    for entry in moves {
        crate::nt_wine_window::position::set(&[entry.window.raw() as u64, entry.insert_after,
            entry.x as u32 as u64, entry.y as u32 as u64, entry.cx as u32 as u64, entry.cy as u32 as u64,
            entry.flags as u64]);
    }
    win_bool(true)
}

/// Showing or hiding owned popups reaches each one through the canonical
/// show path. # C: O(N_windows² )
fn show_owned_popups(owner_window: u64, show: bool) -> u64 {
    for popup in owner::owned_popups_for_current(owner_window, show) {
        crate::nt_wine_window::placement::show(popup as u64, if show { SW_SHOWNORMAL } else { SW_HIDE });
    }
    win_bool(true)
}

const SW_HIDE: u64 = 0;
const SW_SHOWNORMAL: u64 = 1;

/// The internal position query answers the placement's show command and fills
/// the normal rectangle and minimized point the caller asked for.
/// # C: O(N_windows)
fn internal_window_pos(hwnd: u64, rect: u64, point: u64) -> u64 {
    let Some(placement) = crate::nt_wine_window::placement::record(hwnd) else { return 0; };
    if rect != 0 && !write_rect(rect, placement.normal) { return 0; }
    if point != 0 {
        if uaccess::put_user_u32(point, placement.min.0 as u32).is_err()
            || uaccess::put_user_u32(point + 4, placement.min.1 as u32).is_err() { return 0; }
    }
    placement.show as u64
}

fn set_internal_window_pos(args: &[u64]) -> u64 {
    let rect = (args[2] != 0).then(|| read_rect(args[2])).flatten();
    let point = if args[3] == 0 { None } else {
        let (Ok(x), Ok(y)) = (uaccess::get_user_u32(args[3]), uaccess::get_user_u32(args[3] + 4)) else { return 0; };
        Some((x as i32, y as i32))
    };
    crate::nt_wine_window::placement::apply_internal(args[0], args[1] as u32, rect, point);
    STATUS_SUCCESS
}

/// Printing a window asks it to draw itself into the caller's device context.
/// # C: O(window procedure work)
fn print_window(hwnd: u64, dc: u64, flags: u32) -> u64 {
    const PW_CLIENTONLY: u32 = 0x0000_0001;
    const PRF_CLIENT: u64 = 0x0000_0004;
    const PRF_ERASEBKGND: u64 = 0x0000_0008;
    const PRF_CHILDREN: u64 = 0x0000_0010;
    const PRF_OWNED: u64 = 0x0000_0020;
    const PRF_NONCLIENT: u64 = 0x0000_0002;
    const WM_PRINT: u32 = 0x0317;
    let mut print_flags = PRF_CHILDREN | PRF_ERASEBKGND | PRF_OWNED | PRF_CLIENT;
    if flags & PW_CLIENTONLY == 0 { print_flags |= PRF_NONCLIENT; }
    crate::nt_window::send::send_for_current(hwnd, WM_PRINT, dc, print_flags);
    win_bool(true)
}

fn write_rect(address: u64, rect: ipc::win32_window::WindowRect) -> bool {
    [rect.left, rect.top, rect.right, rect.bottom].iter().enumerate()
        .all(|(index, value)| address.checked_add(index as u64 * 4)
            .is_some_and(|slot| uaccess::put_user_u32(slot, *value as u32).is_ok()))
}

fn read_rect(address: u64) -> Option<ipc::win32_window::WindowRect> {
    let read = |offset: u64| uaccess::get_user_u32(address.checked_add(offset)?).ok().map(|value| value as i32);
    Some(ipc::win32_window::WindowRect { left: read(0)?, top: read(4)?, right: read(8)?, bottom: read(12)? })
}
