//! Kernel binding: user copies and the live desktop snapshot for `NtUserCallTwoParam`.
use super::*;
use crate::nt_wine_window::metrics;

pub(crate) fn primary(monitors: &[Monitor]) -> Option<usize> { metrics::primary(monitors).and_then(|p| monitors.iter().position(|m| *m == p)) }

fn read<const N: usize>(pointer: u64) -> Option<[u8; N]> {
    if pointer == 0 { return None; }
    let mut bytes = [0u8; N];
    uaccess::copy_from_user(&mut bytes, pointer).ok().map(|_| bytes)
}

fn unhandled(code: u32) -> u64 {
    klog::write_raw(b"[WINDOWS-RAW-UNHANDLED] ordinal=133e code=");
    klog::write_hex_u64(u64::from(code));
    klog::write_raw(b"\n");
    UNHANDLED
}

/// # C: O(monitors) plus bounded usercopy
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    if ordinal != ORDINAL { return None; }
    let [arg1, arg2, code, ..] = args else { return Some(0); };
    let (arg1, arg2, code) = (*arg1, *arg2, *code as u32);
    Some(match code {
        GET_SYSTEM_METRICS_FOR_DPI => metrics::get(arg1),
        MONITOR_FROM_RECT => {
            let Some(bytes) = read::<RECT_BYTES>(arg1) else { return Some(0); };
            let Some(monitors) = crate::nt_compositor::monitors_current() else { return Some(0); };
            monitor_from_rect(Rect::decode(&bytes).unwrap(), arg2, &monitors, primary(&monitors))
        },
        GET_MONITOR_INFO => {
            let Some(cb) = uaccess::get_user_u32(arg2).ok() else { return Some(0); };
            let Some(monitors) = crate::nt_compositor::monitors_current() else { return Some(0); };
            let Some(bytes) = monitor_info(arg1, cb, &monitors, primary(&monitors)) else { return Some(0); };
            u64::from(uaccess::copy_to_user(arg2, &bytes).is_ok())
        },
        GET_VIRTUAL_SCREEN_RECT => {
            let Some(monitors) = crate::nt_compositor::monitors_current() else { return Some(0); };
            let Some(rect) = virtual_screen_rect(&monitors) else { return Some(0); };
            u64::from(uaccess::copy_to_user(arg1, &rect.encode()).is_ok())
        },
        ADJUST_WINDOW_RECT => {
            let (Some(rect), Some(params)) = (read::<RECT_BYTES>(arg1), read::<ADJUST_PARAMS_BYTES>(arg2)) else { return Some(0); };
            let adjusted = adjust_window_rect(Rect::decode(&rect).unwrap(), AdjustParams::decode(&params).unwrap(), |index| metrics::get(index as u64) as i32);
            u64::from(uaccess::copy_to_user(arg1, &adjusted.encode()).is_ok())
        },
        // The resource menu loader asks this of every submenu handle before
        // it will attach one to an item, so an unanswered query costs every
        // menu its dropdowns.
        GET_MENU_INFO => crate::nt_window::menu_raw::get_menu_info(arg1, arg2),
        // A dialog procedure the client stored as a handle: the caller uses
        // the answer as the procedure to call, so a word that is not one of
        // this process's handles is answered unchanged rather than as null.
        GET_DIALOG_PROC => crate::nt_window::dialog_proc_for_current(arg1, arg2 != 0),
        // The allocation answers the procedure itself when it takes no slot,
        // for the same reason: the caller stores whatever comes back.
        ALLOC_WINPROC => crate::nt_window::alloc_winproc_for_current(arg1, arg2 != 0),
        SET_ICON_PARAM => {
            let Some(bytes) = read::<FREE_ICON_PARAMS_BYTES>(arg2) else { return Some(0); };
            let callback = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
            let param = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
            crate::nt_window::user_input::set_icon_free_params_for_current(arg1, callback, param)
        },
        // The composition rectangle is stated in the window's client space and
        // reaches the display driver in raw desktop space; a word that names no
        // window is refused before any mapping.
        SET_IME_COMPOSITION_RECT => {
            let Some(bytes) = read::<RECT_BYTES>(arg2) else { return Some(0); };
            let Some(rect) = Rect::decode(&bytes) else { return Some(0); };
            u64::from(crate::nt_window::set_ime_composition_rect_for_current(arg1, rect.left, rect.top, rect.right, rect.bottom))
        },
        other => unhandled(other),
    })
}
