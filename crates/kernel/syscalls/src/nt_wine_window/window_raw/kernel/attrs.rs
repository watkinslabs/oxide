//! Style, attribute, foreground and record-writing ordinals.
use super::*;
use ipc::win32_window::{LayeredAttributes, WindowRect};
use crate::nt_window as owner;

/// # C: O(window owner work plus bounded usercopy)
pub(super) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    Some(match ordinal {
        ALTER_WINDOW_STYLE => win_bool(owner::alter_style_for_current(args[0], args[1] as u32, args[2] as u32)),
        ENABLE_WINDOW => enable(args[0], args[1] != 0),
        GET_WINDOW_CONTEXT_HELP_ID => owner::help_context_for_current(args[0]) as u64,
        SET_WINDOW_CONTEXT_HELP_ID => win_bool(owner::set_help_context_for_current(args[0], args[1] as u32)),
        GET_WINDOW_DISPLAY_AFFINITY => display_affinity(args[0], args[1]),
        GET_LAYERED_ATTRIBUTES => layered(args[0], args[1], args[2], args[3]),
        SET_LAYERED_ATTRIBUTES => win_bool(owner::set_layered_attributes_for_current(args[0],
            LayeredAttributes { color_key: args[1] as u32, alpha: args[2] as u8, flags: args[3] as u32 })),
        UPDATE_LAYERED_WINDOW => update_layered(args),
        GET_WINDOW_RGN_EX => window_region(args[0]),
        SET_WINDOW_RGN => set_window_region(args[0], args[1]),
        GET_TITLE_BAR_INFO => title_bar_info(args[0], args[1]),
        GET_GUI_THREAD_INFO => gui_thread_info(args[1]),
        GET_FOREGROUND_WINDOW => owner::foreground_window(),
        SET_FOREGROUND_WINDOW => win_bool(owner::set_foreground_window(args[0])),
        LOCK_WINDOW_UPDATE => win_bool(owner::lock_window_update(args[0])),
        SET_SHELL_WINDOW_EX => win_bool(owner::set_shell_window(args[0], args[1])),
        SET_PROGMAN_WINDOW => owner::set_progman_window(args[0]),
        SET_TASKMAN_WINDOW => owner::set_taskman_window(args[0]),
        FLASH_WINDOW_EX => flash(args[0]),
        _ => return None,
    })
}

/// EnableWindow answers whether the window was already disabled, and the
/// transition it reports drives the messages the caller sends.
/// # C: O(N_windows)
fn enable(hwnd: u64, enable: bool) -> u64 {
    let Some(outcome) = owner::enable_window_for_current(hwnd, enable) else { return win_bool(false); };
    win_bool(outcome.previously_disabled)
}

fn display_affinity(hwnd: u64, out: u64) -> u64 {
    if hwnd == 0 || out == 0 {
        owner::report_last_error(if hwnd == 0 { ERROR_INVALID_WINDOW_HANDLE } else { ERROR_NOACCESS });
        return win_bool(false);
    }
    let Some(affinity) = owner::display_affinity_for_current(hwnd) else { return win_bool(false); };
    win_bool(uaccess::put_user_u32(out, affinity).is_ok())
}

/// The layered query fills only the outputs the caller asked for, and a window
/// with no layered appearance reports nothing at all. # C: O(N_windows)
fn layered(hwnd: u64, key: u64, alpha: u64, flags: u64) -> u64 {
    let Some(attributes) = owner::layered_attributes_for_current(hwnd) else { return win_bool(false); };
    if key != 0 && uaccess::put_user_u32(key, attributes.color_key).is_err() { return win_bool(false); }
    if alpha != 0 && !crate::nt_wine_window::user_write::put_user_u8(alpha, attributes.alpha) { return win_bool(false); }
    if flags != 0 && uaccess::put_user_u32(flags, attributes.flags).is_err() { return win_bool(false); }
    win_bool(true)
}

/// A per-pixel layered update is admitted against the window's styles and the
/// size the caller asks for; the pixels themselves travel through the device
/// contexts the caller already owns. # C: O(N_windows)
fn update_layered(args: &[u64]) -> u64 {
    let Some(flags) = crate::nt_dispatch::stack_argument(8) else { return win_bool(false); };
    let size = if args[3] == 0 { None } else {
        let (Ok(cx), Ok(cy)) = (uaccess::get_user_u32(args[3]), uaccess::get_user_u32(args[3] + 4))
            else { return win_bool(false); };
        Some((cx as i32, cy as i32))
    };
    if !owner::admit_layered_update_for_current(args[0], flags as u32, size) {
        owner::report_last_error(ERROR_INVALID_PARAMETER);
        return win_bool(false);
    }
    win_bool(true)
}

/// The region query reports whether the window has one at all; the rectangles
/// themselves are combined into the caller's region by the region owner.
/// # C: O(N_windows + N_rects)
fn window_region(hwnd: u64) -> u64 {
    // ERROR is the answer for a window with no region, and the region kind
    // otherwise: a single rectangle is simple, more than one is complex.
    const ERROR: u64 = 0;
    const SIMPLEREGION: u64 = 2;
    const COMPLEXREGION: u64 = 3;
    match owner::window_region_for_current(hwnd) {
        None => ERROR,
        Some(rects) if rects.len() <= 1 => SIMPLEREGION,
        Some(_) => COMPLEXREGION,
    }
}

fn set_window_region(hwnd: u64, region: u64) -> u64 {
    if region == 0 { return win_bool(owner::set_window_region_for_current(hwnd, None)); }
    let Ok(snapshot) = crate::nt_gdi::region_snapshot_for_current(region) else { return win_bool(false); };
    win_bool(owner::set_window_region_for_current(hwnd, Some(snapshot.rects())))
}

fn title_bar_info(hwnd: u64, info: u64) -> u64 {
    if info == 0 { owner::report_last_error(ERROR_NOACCESS); return win_bool(false); }
    let Ok(declared) = uaccess::get_user_u32(info + TITLEBARINFO_SIZE) else { return win_bool(false); };
    if !record_size_matches(declared, TITLEBARINFO_BYTES) {
        owner::report_last_error(ERROR_INVALID_PARAMETER);
        return win_bool(false);
    }
    let Some((rect, state)) = owner::title_bar_state_for_current(hwnd) else { return win_bool(false); };
    if !write_rect(info + TITLEBARINFO_RECT, rect) { return win_bool(false); }
    for (index, value) in state.iter().enumerate() {
        let Some(address) = info.checked_add(TITLEBARINFO_STATE + index as u64 * 4) else { return win_bool(false); };
        if uaccess::put_user_u32(address, *value).is_err() { return win_bool(false); }
    }
    win_bool(true)
}

fn gui_thread_info(info: u64) -> u64 {
    if info == 0 { return win_bool(false); }
    let Ok(declared) = uaccess::get_user_u32(info + GUITHREADINFO_SIZE) else { return win_bool(false); };
    if !record_size_matches(declared, GUITHREADINFO_BYTES) {
        owner::report_last_error(ERROR_INVALID_PARAMETER);
        return win_bool(false);
    }
    let found = owner::gui_thread_info();
    let (active, focus, capture, caret, caret_rect) = found.unwrap_or((None, None, None, None,
        WindowRect { left: 0, top: 0, right: 0, bottom: 0 }));
    let handle = |window: Option<ipc::win32_window::WindowId>| window.map_or(0, |id| id.raw() as u64);
    let mut flags = 0;
    if caret.is_some() { flags |= GUI_CARETBLINKING; }
    let writes = [(GUITHREADINFO_ACTIVE, handle(active)), (GUITHREADINFO_FOCUS, handle(focus)),
        (GUITHREADINFO_CAPTURE, handle(capture)), (GUITHREADINFO_MENU_OWNER, 0),
        (GUITHREADINFO_MOVE_SIZE, 0), (GUITHREADINFO_CARET, handle(caret))];
    if uaccess::put_user_u32(info + GUITHREADINFO_FLAGS, flags).is_err() { return win_bool(false); }
    for (offset, value) in writes {
        if uaccess::put_user_u64(info + offset, value).is_err() { return win_bool(false); }
    }
    win_bool(write_rect(info + GUITHREADINFO_CARET_RECT, caret_rect))
}

/// Flashing marks the non-client area active, or stops when no flags are
/// given. The call answers the state the window had. # C: O(N_windows)
fn flash(info: u64) -> u64 {
    if info == 0 { owner::report_last_error(ERROR_NOACCESS); return win_bool(false); }
    let (Ok(declared), Ok(hwnd), Ok(flags)) = (uaccess::get_user_u32(info + FLASHWINFO_SIZE),
        uaccess::get_user_u64(info + FLASHWINFO_HWND), uaccess::get_user_u32(info + FLASHWINFO_FLAGS))
        else { return win_bool(false); };
    if hwnd == 0 || !record_size_matches(declared, FLASHWINFO_BYTES) || !owner::window_is_live(hwnd) {
        owner::report_last_error(ERROR_INVALID_PARAMETER);
        return win_bool(false);
    }
    let already = owner::nc_activated_for_current(hwnd);
    let answer = if flags == 0 { hwnd == owner::foreground_window() } else { !already };
    if let Some(active) = flash_activates(flags, already) { owner::set_nc_activated_for_current(hwnd, active); }
    win_bool(answer)
}

fn write_rect(address: u64, rect: WindowRect) -> bool {
    let values = [rect.left, rect.top, rect.right, rect.bottom];
    values.iter().enumerate().all(|(index, value)| address.checked_add(index as u64 * 4)
        .is_some_and(|slot| uaccess::put_user_u32(slot, *value as u32).is_ok()))
}
