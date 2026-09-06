//! Wine x86-64 win32u syscall ordinal adapter.

use syscall::{nt::{NtCall, NtService}, SyscallArgs};

// PFN ABI normalization and table bounds, shared with the RTL entry.
pub(crate) mod pfn;
mod metrics;
pub(crate) mod hwnd_call;
mod msg_filter;
mod two_param;
pub(crate) mod accel_raw;
pub(crate) mod dpi_context;
pub(crate) mod builtin_classes;
pub(crate) mod unclaimed;
mod geometry;
mod hwnd_param;
mod long_raw;
#[cfg(target_os = "oxide-kernel")]
mod message_send;
pub(crate) mod placement;
pub(crate) mod position;
mod gdi_raw;
mod gdi_route;
mod bitmap_raw;
mod brush_raw;
mod clip_raw;
#[cfg(target_os = "oxide-kernel")]
mod property_raw;
#[cfg(target_os = "oxide-kernel")]
mod caret_raw;
#[path = "nt_wine_window/object_raw.rs"]
mod object_raw;
#[cfg(target_os = "oxide-kernel")]
mod create_context;

#[cfg(target_os = "oxide-kernel")]
mod raw_class;
#[cfg(target_os = "oxide-kernel")]
mod raw_callback;
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
mod raw_args;

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
const STATUS_SUCCESS: u64 = 0;

const WINE_CREATE_WINDOW_EX: u64 = 0x136b;
const WINE_GET_MESSAGE: u64 = 0x141b;
const WINE_DESTROY_WINDOW: u64 = 0x1384;
const WINE_PEEK_MESSAGE: u64 = 0x14ca;
const WINE_POST_MESSAGE: u64 = 0x14d0;
const WINE_SHOW_WINDOW: u64 = 0x15bd;
const WINE_BEGIN_PAINT: u64 = 0x1327;
const WINE_END_PAINT: u64 = 0x13bc;
const WINE_GET_DC: u64 = 0x13eb;
const WINE_GET_DC_EX: u64 = 0x13ec;
const WINE_INVALIDATE_RECT: u64 = 0x148c;
const WINE_RELEASE_DC: u64 = 0x1509;
const WINE_SET_WINDOW_POS: u64 = 0x15a7;
const WINE_MOVE_WINDOW: u64 = 0x14ba;
#[cfg(test)]
use gdi_raw::{GET_TEXT_METRICS_W as WINE_GET_TEXT_METRICS, GET_TEXT_EXTENT_EX_W as WINE_GET_TEXT_EXTENT_EX};
const WINE_REGISTER_CLASS_EX: u64 = 0x14eb;
const WINE_DISPATCH_MESSAGE: u64 = 0x138b;
const WINE_MESSAGE_CALL: u64 = 0x14b5;
const WINE_GET_CLASS_NAME: u64 = 0x13d9;
const WINE_GET_CLASS_INFO_EX: u64 = 0x13d8;
const WINE_UNREGISTER_CLASS: u64 = 0x15df;
const WINE_REGISTER_WINDOW_MESSAGE: u64 = 0x1507;
const WINE_CLOSE_CLIPBOARD: u64 = 0x1351;
const WINE_OPEN_CLIPBOARD: u64 = 0x14c2;
// Wine's NtUserCallWindowProc selector, passed as the NtUserMessageCall type.
const WINE_CALL_WINDOW_PROC: u64 = 0x02ab;
// Wine's builtin DefWindowProc selector, passed through the same syscall.
const WINE_DEF_WINDOW_PROC: u64 = 0x029e;

// Wine's generated win32u syscall table assigns this ordinal to the raw
// four-argument client-table publication entry.
const WINE_NTUSER_INITIALIZE_CLIENT_PFN_ARRAYS: u64 = 0x147a;
const WINE_NTUSER_GET_SYSTEM_DPI_FOR_PROCESS: u64 = 0x144b;
const WINE_GET_WINDOW_PLACEMENT: u64 = 0x1463;
const WINE_SET_WINDOW_PLACEMENT: u64 = 0x15a6;
const WINE_GET_ASYNC_KEY_STATE: u64 = 0x13d0;
const WINE_GET_KEY_STATE: u64 = 0x1410;
const WINE_GET_KEYBOARD_STATE: u64 = 0x1414;
const WINE_SET_KEYBOARD_STATE: u64 = 0x1565;
const WINE_CALL_NO_PARAM: u64 = 0x133c;
const WINE_CHECK_MENU_ITEM: u64 = 0x1347;
const WINE_CREATE_MENU: u64 = 0x1366;
const WINE_CREATE_POPUP_MENU: u64 = 0x1368;
const WINE_DELETE_MENU: u64 = 0x1378;
const WINE_REMOVE_MENU: u64 = 0x151d;
const WINE_GET_MENU_BAR_INFO: u64 = 0x1418;
const WINE_GET_MENU_ITEM_RECT: u64 = 0x141a;
const WINE_DRAW_MENU_BAR: u64 = 0x139b;
const WINE_DRAW_MENU_BAR_TEMP: u64 = 0x139c;
const WINE_SET_ACTIVE_WINDOW: u64 = 0x1532;
const WINE_SET_FOCUS: u64 = 0x1557;
const WINE_TRANSLATE_MESSAGE: u64 = 0x15d8;
const WINE_DESTROY_MENU: u64 = 0x1382;
const WINE_ENABLE_MENU_ITEM: u64 = 0x13a7;
const WINE_SET_MENU: u64 = 0x1569;
const WINE_THUNKED_MENU_ITEM_INFO: u64 = 0x15d0;
const WINE_CALL_ONE_PARAM: u64 = 0x133d;
const CALL_ONE_PARAM_GET_MENU_ITEM_COUNT: u64 = 4;
const CALL_NO_PARAM_GET_DIALOG_BASE_UNITS: u64 = 1;
const WM_TIMER: u32 = 0x0113;
const WM_SETTEXT: u64 = 0x000c;
const WM_GETTEXT: u64 = 0x000d;
const WM_GETTEXTLENGTH: u64 = 0x000e;
const WM_NCCREATE: u64 = 0x0081;
const WM_NCDESTROY: u64 = 0x0082;
const WM_NCHITTEST: u64 = 0x0084;
const WM_NCACTIVATE: u64 = 0x0086;
// `struct win_proc_params` from Wine's ntuser.h.  The layout is stable for
// the x86-64 client ABI used by the image: pointers are eight bytes, followed
// by the 32-bit message/flag fields.
const WIN_PROC_HWND: u64 = 8;
const WIN_PROC_MSG: u64 = 16;
const WIN_PROC_WPARAM: u64 = 24;
const WIN_PROC_LPARAM: u64 = 32;
const WIN_PROC_ANSI: u64 = 40;
const WIN_PROC_ANSI_DST: u64 = 44;
const WIN_PROC_MAPPING: u64 = 48;
const WIN_PROC_DPI_CONTEXT: u64 = 52;
const WIN_PROC_PROCA: u64 = 56;
const WIN_PROC_PROCW: u64 = 64;
const WIN_PROC_CALLWINDOWPROC_MAPPING: u32 = 5;

fn message_field(base: u64, offset: u64) -> Option<u64> { base.checked_add(offset) }

/// Fill Wine's `win_proc_params` record for `NtUserCallWindowProc`.
///
/// Wine deliberately separates this operation from the later client-side
/// callback: `NtUserMessageCall` initializes the record and returns TRUE;
/// user32 then dispatches the procedure using the populated record. Keeping
/// that boundary intact prevents the kernel from invoking a WndProc once here
/// and once again in the client.
#[cfg(target_os = "oxide-kernel")]
pub(super) fn initialize_window_proc_params(pointer: u64, hwnd: u64, message: u64,
                                             wparam: u64, lparam: u64, ansi: u64) -> u64 {
    if pointer == 0 || !uaccess::access_ok(pointer, (WIN_PROC_PROCW + 8) as usize) {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(func) = uaccess::get_user_u64(pointer).ok().filter(|value| *value != 0) else {
        return STATUS_INVALID_PARAMETER;
    };
    let writes = [
        (WIN_PROC_HWND, hwnd), (WIN_PROC_WPARAM, wparam),
        (WIN_PROC_LPARAM, lparam), (WIN_PROC_PROCA, func),
        (WIN_PROC_PROCW, func),
    ];
    for (offset, value) in writes {
        if uaccess::put_user_u64(pointer.saturating_add(offset), value).is_err() {
            return STATUS_INVALID_PARAMETER;
        }
    }
    for (offset, value) in [
        (WIN_PROC_MSG, message as u32), (WIN_PROC_ANSI, (ansi != 0) as u32),
        (WIN_PROC_ANSI_DST, (ansi != 0) as u32),
        (WIN_PROC_MAPPING, WIN_PROC_CALLWINDOWPROC_MAPPING),
        (WIN_PROC_DPI_CONTEXT, 0),
    ] {
        if uaccess::put_user_u32(pointer.saturating_add(offset), value).is_err() {
            return STATUS_INVALID_PARAMETER;
        }
    }
    1
}

/// Keep the raw ordinal admission decision independent of the kernel entry
/// body so hosted tests exercise the same claim boundary.
/// # C: O(1)
fn raw_ordinal_claimed(ordinal: u64) -> bool {
    matches!(ordinal,
        WINE_CREATE_WINDOW_EX | WINE_REGISTER_CLASS_EX | WINE_DISPATCH_MESSAGE | WINE_MESSAGE_CALL |
        WINE_GET_MESSAGE | WINE_DESTROY_WINDOW | WINE_PEEK_MESSAGE |
        WINE_POST_MESSAGE | WINE_SHOW_WINDOW | WINE_BEGIN_PAINT | WINE_END_PAINT |
        WINE_GET_DC | WINE_GET_DC_EX | WINE_INVALIDATE_RECT | WINE_RELEASE_DC |
        WINE_SET_WINDOW_POS | WINE_MOVE_WINDOW | WINE_SET_WINDOW_PLACEMENT | WINE_GET_ASYNC_KEY_STATE | WINE_GET_KEY_STATE |
        WINE_GET_KEYBOARD_STATE | WINE_SET_KEYBOARD_STATE |
        WINE_GET_CLASS_INFO_EX | WINE_GET_CLASS_NAME |
        WINE_REGISTER_WINDOW_MESSAGE |
        WINE_CLOSE_CLIPBOARD | WINE_OPEN_CLIPBOARD |
        WINE_NTUSER_INITIALIZE_CLIENT_PFN_ARRAYS |
        WINE_NTUSER_GET_SYSTEM_DPI_FOR_PROCESS | WINE_GET_WINDOW_PLACEMENT | WINE_CALL_NO_PARAM |
        WINE_CHECK_MENU_ITEM | WINE_CREATE_MENU | WINE_CREATE_POPUP_MENU | WINE_DELETE_MENU |
        WINE_REMOVE_MENU | WINE_GET_MENU_BAR_INFO | WINE_GET_MENU_ITEM_RECT | WINE_DRAW_MENU_BAR |
        WINE_DRAW_MENU_BAR_TEMP | WINE_SET_ACTIVE_WINDOW | WINE_SET_FOCUS | WINE_TRANSLATE_MESSAGE |
        WINE_DESTROY_MENU | WINE_ENABLE_MENU_ITEM | WINE_SET_MENU | WINE_THUNKED_MENU_ITEM_INFO |
        WINE_CALL_ONE_PARAM)
}

#[cfg(target_os = "oxide-kernel")]
fn read_args(pointer: u64) -> Option<[u64; 17]> {
    let mut args = [0u64; 17];
    for (index, value) in args.iter_mut().enumerate() {
        let address = pointer.checked_add((index * 8) as u64)?;
        *value = uaccess::get_user_u64(address).ok()?;
    }
    Some(args)
}

#[cfg(target_os = "oxide-kernel")]
fn read_unicode_string(pointer: u64) -> Option<alloc::vec::Vec<u16>> {
    let length = read_user_u16(pointer)? as usize;
    if length == 0 || length & 1 != 0 || length > 512 { return None; }
    let buffer = uaccess::get_user_u64(pointer.checked_add(8)?).ok()?;
    if buffer == 0 { return None; }
    let mut value = alloc::vec::Vec::new();
    value.try_reserve_exact(length / 2).ok()?;
    for index in 0..length / 2 {
        value.push(read_user_u16(buffer.checked_add((index * 2) as u64)?)?);
    }
    Some(value)
}

#[cfg(target_os = "oxide-kernel")]
fn read_optional_unicode_string(pointer: u64) -> Option<alloc::vec::Vec<u16>> {
    if pointer == 0 { return Some(alloc::vec::Vec::new()); }
    let length = read_user_u16(pointer)? as usize;
    if length & 1 != 0 || length > 512 { return None; }
    if length == 0 { return Some(alloc::vec::Vec::new()); }
    let buffer = uaccess::get_user_u64(pointer.checked_add(8)?).ok()?;
    if buffer == 0 { return None; }
    let mut value = alloc::vec::Vec::new();
    value.try_reserve_exact(length / 2).ok()?;
    for index in 0..length / 2 { value.push(read_user_u16(buffer.checked_add((index * 2) as u64)?)?); }
    Some(value)
}

#[cfg(target_os = "oxide-kernel")]
fn read_user_u16(address: u64) -> Option<u16> {
    let mut bytes = [0u8; 2];
    uaccess::copy_from_user(&mut bytes, address).ok()?;
    Some(u16::from_le_bytes(bytes))
}

#[cfg(target_os = "oxide-kernel")]
#[path = "nt_wine_window/dispatch.rs"]
mod dispatch;
#[cfg(target_os = "oxide-kernel")]
pub use dispatch::{dispatch, dispatch_raw, dispatch_raw_linux};

#[cfg(target_os = "oxide-kernel")]
fn draw_menu_bar_temp(args: &[u64; 17]) -> u64 {
    if args[2] == 0 { return 0; }
    let menu = if args[3] != 0 { args[3] } else { crate::nt_window::window_menu_for_current(args[0]).unwrap_or(0) };
    let Some(rect) = crate::nt_window::menu_bar_rect_for_current_menu(args[0], menu) else { return 0; };
    let mut raw = [0u8; 16];
    for (index, value) in [rect.left, rect.top, rect.right, rect.bottom].iter().enumerate() {
        raw[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    if uaccess::copy_to_user(args[2], &raw).is_err() { 0 } else { rect.bottom.saturating_sub(rect.top) as u64 }
}

#[cfg(target_os = "oxide-kernel")]
fn get_class_name(args: &[u64; 17]) -> u64 {
    let Some(name) = crate::nt_window::window_class_name_for_current(args[0]) else { return STATUS_INVALID_PARAMETER; };
    if args[2] == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(maximum_address) = message_field(args[2], 2) else { return STATUS_INVALID_PARAMETER; };
    let Some(buffer_address) = message_field(args[2], 8) else { return STATUS_INVALID_PARAMETER; };
    let Some(maximum) = read_user_u16(maximum_address) else { return STATUS_INVALID_PARAMETER; };
    let Ok(buffer) = uaccess::get_user_u64(buffer_address) else { return STATUS_INVALID_PARAMETER; };
    if buffer == 0 || maximum < 2 { return STATUS_INVALID_PARAMETER; }
    let capacity = (maximum as usize / 2).saturating_sub(1);
    let copied = name.len().min(capacity);
    for (index, unit) in name.iter().take(copied).enumerate() {
        let Some(offset) = (index as u64).checked_mul(2) else { return STATUS_INVALID_PARAMETER; };
        let Some(address) = buffer.checked_add(offset) else { return STATUS_INVALID_PARAMETER; };
        if uaccess::copy_to_user(address, &unit.to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    }
    let Some(offset) = (copied as u64).checked_mul(2) else { return STATUS_INVALID_PARAMETER; };
    let Some(terminator) = buffer.checked_add(offset) else { return STATUS_INVALID_PARAMETER; };
    if uaccess::copy_to_user(terminator, &[0, 0]).is_err() { return STATUS_INVALID_PARAMETER; }
    if uaccess::copy_to_user(args[2], &(copied as u16 * 2).to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    copied as u64
}

#[cfg(target_os = "oxide-kernel")]
fn get_class_info_ex(args: &[u64; 17]) -> u64 {
    let info = if args[1] <= u16::MAX as u64 {
        crate::nt_window::class_info_by_atom_for_current(args[1] as u16)
    } else {
        let Some(name) = read_unicode_string(args[1]) else { return 0; };
        crate::nt_window::class_info_for_current(&name)
    };
    let Some((_, wndproc, _, extra)) = info else { return 0; };
    if args[2] == 0 { return 0; }
    let mut bytes = [0u8; 80];
    bytes[0..4].copy_from_slice(&80u32.to_le_bytes());
    bytes[8..16].copy_from_slice(&wndproc.to_le_bytes());
    bytes[20..24].copy_from_slice(&extra.to_le_bytes());
    bytes[32..40].copy_from_slice(&args[0].to_le_bytes());
    if uaccess::copy_to_user(args[2], &bytes).is_err() { return 0; }
    1
}


#[cfg(target_os = "oxide-kernel")]
fn translate_raw_message(pointer: u64) -> u64 {
    const WM_KEYDOWN: u32 = 0x0100;
    const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
    if pointer == 0 { return STATUS_INVALID_PARAMETER; }
    // The first 32 bytes of the x86-64 Windows MSG are the stable fields
    // shared with NtWindowMessage: HWND, message, wParam, and lParam.
    let mut bytes = [0u8; 32];
    if uaccess::copy_from_user(&mut bytes, pointer).is_err() { return STATUS_ACCESS_VIOLATION; }
    let hwnd = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let message = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let wparam = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let lparam = i64::from_le_bytes(bytes[24..32].try_into().unwrap());
    if crate::nt_compositor::monitors_current().is_some() {
        // Desktop text already carries the active XKB layout's translation.
        // Reapplying the legacy US-key conversion would duplicate every WM_CHAR
        // and turn shortcuts into literal letters. Wine accepts the keyboard
        // message range even when no character is produced (message.c).
        return (0x0100..=0x0109).contains(&message) as u64;
    }
    if message != WM_KEYDOWN { return 0; }
    let Some(character) = translated_key(wparam as u16) else { return 0; };
    let status = crate::nt_window::dispatch(NtCall {
        service: NtService::PostMessage,
        args: SyscallArgs { a0: hwnd, a1: 0x0102, a2: character as u64, a3: lparam as u64, a4: 0, a5: 0 },
    }).unwrap_or(STATUS_INVALID_PARAMETER);
    (status == STATUS_SUCCESS) as u64
}

#[cfg(target_os = "oxide-kernel")]
fn keyboard_query(ordinal: u64, value: u64) -> Option<u64> {
    Some(match ordinal {
        WINE_GET_ASYNC_KEY_STATE => crate::nt_window::get_async_key_state_current(value),
        WINE_GET_KEY_STATE => crate::nt_window::get_key_state_current(value),
        WINE_GET_KEYBOARD_STATE => crate::nt_window::get_keyboard_state_current(value),
        WINE_SET_KEYBOARD_STATE => crate::nt_window::set_keyboard_state_current(value),
        _ => return None,
    })
}

fn translated_key(key: u16) -> Option<u16> {
    match key {
        0x08 | 0x09 | 0x0d | 0x20 => Some(key),
        0x30..=0x39 | 0x41..=0x5a => Some(if (0x41..=0x5a).contains(&key) { key + 0x20 } else { key }),
        _ => None,
    }
}

#[cfg(target_os = "oxide-kernel")]
fn win_bool(status: u64) -> u64 { (status == STATUS_SUCCESS) as u64 }

#[cfg(target_os = "oxide-kernel")]
pub(crate) mod paint;
#[cfg(target_os = "oxide-kernel")]
use paint::{begin_paint, end_paint};
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wine_user32_ordinals_match_the_generated_table() {
        assert_eq![(WINE_CREATE_WINDOW_EX, 0x136b), (WINE_DESTROY_WINDOW, 0x1384), (WINE_GET_MESSAGE, 0x141b), (WINE_PEEK_MESSAGE, 0x14ca), (WINE_POST_MESSAGE, 0x14d0), (WINE_SHOW_WINDOW, 0x15bd), (WINE_BEGIN_PAINT, 0x1327), (WINE_END_PAINT, 0x13bc), (WINE_GET_DC, 0x13eb), (WINE_GET_DC_EX, 0x13ec), (WINE_INVALIDATE_RECT, 0x148c), (WINE_RELEASE_DC, 0x1509), (WINE_SET_WINDOW_POS, 0x15a7), (WINE_GET_TEXT_METRICS, 0x1229), (WINE_GET_TEXT_EXTENT_EX, 0x1227), (WINE_REGISTER_CLASS_EX, 0x14eb), (WINE_DISPATCH_MESSAGE, 0x138b), (WINE_MESSAGE_CALL, 0x14b5), (WINE_GET_CLASS_NAME, 0x13d9), (WINE_GET_CLASS_INFO_EX, 0x13d8), (WINE_UNREGISTER_CLASS, 0x15df), (WINE_REGISTER_WINDOW_MESSAGE, 0x1507), (WINE_CLOSE_CLIPBOARD, 0x1351), (WINE_OPEN_CLIPBOARD, 0x14c2), (WINE_NTUSER_INITIALIZE_CLIENT_PFN_ARRAYS, 0x147a), (WINE_NTUSER_GET_SYSTEM_DPI_FOR_PROCESS, 0x144b), (WINE_GET_WINDOW_PLACEMENT, 0x1463), (WINE_CALL_NO_PARAM, 0x133c), (WINE_CALL_ONE_PARAM, 0x133d), (WINE_CREATE_MENU, 0x1366), (WINE_CREATE_POPUP_MENU, 0x1368), (WINE_DELETE_MENU, 0x1378), (WINE_REMOVE_MENU, 0x151d), (WINE_DRAW_MENU_BAR, 0x139b), (WINE_DRAW_MENU_BAR_TEMP, 0x139c), (WINE_SET_ACTIVE_WINDOW, 0x1532), (WINE_SET_FOCUS, 0x1557), (WINE_TRANSLATE_MESSAGE, 0x15d8), (WINE_THUNKED_MENU_ITEM_INFO, 0x15d0)] .iter().for_each(|(actual, expected)| assert_eq!(*actual, *expected));
        assert_eq!(WINE_DEF_WINDOW_PROC, 0x029e);
        assert_eq!(WINE_CALL_WINDOW_PROC, 0x02ab);
    }

    #[test]
    fn raw_ordinal_admission_has_positive_and_negative_controls() {
        assert!(raw_ordinal_claimed(WINE_GET_MESSAGE));
        assert!(raw_ordinal_claimed(WINE_BEGIN_PAINT));
        assert!(raw_ordinal_claimed(WINE_REGISTER_WINDOW_MESSAGE));
        assert!(raw_ordinal_claimed(WINE_OPEN_CLIPBOARD));
        assert!(raw_ordinal_claimed(WINE_CLOSE_CLIPBOARD));
        assert!(raw_ordinal_claimed(WINE_GET_CLASS_INFO_EX));
        assert!(raw_ordinal_claimed(WINE_GET_CLASS_NAME));
        assert!(!raw_ordinal_claimed(0x131b));
        assert!(!raw_ordinal_claimed(u64::MAX));
    }

    #[test]
    fn message_offsets_fail_closed_on_pointer_wrap() {
        assert_eq!(message_field(u64::MAX, 0), Some(u64::MAX));
        assert_eq!(message_field(u64::MAX, 8), None);
        assert_eq!(message_field(u64::MAX - 24, 24), Some(u64::MAX));
    }

    #[test]
    fn win_proc_params_layout_matches_wine_ntuser_header() {
        assert_eq!(WIN_PROC_HWND, 8);
        assert_eq!(WIN_PROC_MSG, 16);
        assert_eq!(WIN_PROC_WPARAM, 24);
        assert_eq!(WIN_PROC_LPARAM, 32);
        assert_eq!(WIN_PROC_ANSI, 40);
        assert_eq!(WIN_PROC_ANSI_DST, 44);
        assert_eq!(WIN_PROC_MAPPING, 48);
        assert_eq!(WIN_PROC_DPI_CONTEXT, 52);
        assert_eq!(WIN_PROC_PROCA, 56);
        assert_eq!(WIN_PROC_PROCW, 64);
        assert_eq!(WIN_PROC_PROCW + 8, 72);
        assert_eq!(WIN_PROC_CALLWINDOWPROC_MAPPING, 5);
    }

    #[test]
    fn wine_menuiteminfo_masks_match_win32_contract() {
        assert_eq!(crate::nt_window::MENUITEMINFO_MASK_STATE, 0x0000_0001);
        assert_eq!(crate::nt_window::MENUITEMINFO_MASK_ID, 0x0000_0002);
        assert_eq!(crate::nt_window::MENUITEMINFO_MASK_SUBMENU, 0x0000_0004);
        assert_eq!(crate::nt_window::MENUITEMINFO_MASK_STRING, 0x0000_0040);
    }

    #[test]
    fn raw_translate_key_contract_is_bounded() {
        assert_eq!(translated_key(b'A' as u16), Some(b'a' as u16));
        assert_eq!(translated_key(b'7' as u16), Some(b'7' as u16));
        assert_eq!(translated_key(0x0d), Some(0x0d));
        assert_eq!(translated_key(0x70), None);
    }
}
