//! Tree, point-search, enumeration and text ordinals.
use super::*;
use alloc::vec::Vec;
use ipc::win32_window::HwndListFilter;
use crate::nt_window as owner;

const UNICODE_STRING_LENGTH: u64 = 0;
const UNICODE_STRING_BUFFER: u64 = 8;
/// Longest class or title string a search carries.
const MAX_SEARCH_UNITS: usize = 260;

/// Read one counted UTF-16 string. A record with no buffer is absent, which is
/// how the search calls express "any class" and "any title". # C: O(N_units)
fn unicode_string(address: u64) -> Option<Vec<u16>> {
    if address == 0 { return None; }
    let length = uaccess::get_user_u16(address + UNICODE_STRING_LENGTH).ok()?;
    let buffer = uaccess::get_user_u64(address + UNICODE_STRING_BUFFER).ok()?;
    let units = (length as usize / 2).min(MAX_SEARCH_UNITS);
    if buffer == 0 { return None; }
    let mut owned = Vec::new();
    owned.try_reserve_exact(units).ok()?;
    for index in 0..units { owned.push(uaccess::get_user_u16(buffer.checked_add(index as u64 * 2)?).ok()?); }
    Some(owned)
}

/// # C: O(window owner work plus bounded usercopy)
pub(super) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    Some(match ordinal {
        GET_ANCESTOR => owner::ancestor_for_current(args[0], args[1] as u32),
        CHILD_WINDOW_FROM_POINT_EX => owner::child_from_point_for_current(args[0], args[1] as u32 as i32, args[2] as u32 as i32, args[3] as u32),
        REAL_CHILD_WINDOW_FROM_POINT => owner::child_from_point_for_current(args[0], args[1] as u32 as i32, args[2] as u32 as i32, real_child_flags()),
        WINDOW_FROM_POINT => owner::window_from_point_for_current(args[0] as u32 as i32, args[1] as u32 as i32).0,
        WINDOW_FROM_DC => owner::window_from_dc_for_current(args[0]),
        SET_PARENT => owner::set_parent_for_current(args[0], args[1]).unwrap_or(0),
        FIND_WINDOW_EX => {
            // An empty class string is not the same as no class at all: it
            // names a class no window can have, so nothing matches.
            if args[2] != 0 && unicode_string(args[2]).is_none() { return Some(0); }
            let class = unicode_string(args[2]);
            let title = unicode_string(args[3]);
            let title = if args[3] != 0 && title.is_none() { Some(Vec::new()) } else { title };
            owner::find_window_for_current(args[0], args[1], class.as_deref(), title.as_deref())
        }
        INTERNAL_GET_WINDOW_TEXT => internal_text(args[0], args[1], args[2] as u32 as i32),
        BUILD_HWND_LIST => build_hwnd_list(args),
        BUILD_PROP_LIST => build_prop_list(args[0], args[1] as u32, args[2], args[3]),
        _ => return None,
    })
}

/// Copy one window's text into the caller's buffer, answering the units
/// written. The answer never counts the terminator. # C: O(N_windows + N_text)
fn internal_text(hwnd: u64, buffer: u64, count: i32) -> u64 {
    if count <= 0 || buffer == 0 { return 0; }
    let mut text = Vec::new();
    if owner::internal_window_text_for_current(hwnd, &mut text).is_none() { return 0; }
    let units = text.len().min(count as usize - 1);
    for index in 0..units {
        let Some(address) = buffer.checked_add(index as u64 * 2) else { return 0; };
        if !crate::nt_wine_window::user_write::put_user_u16(address, text[index]) { return 0; }
    }
    let Some(terminator) = buffer.checked_add(units as u64 * 2) else { return 0; };
    if !crate::nt_wine_window::user_write::put_user_u16(terminator, 0) { return 0; }
    units as u64
}

/// Fill one handle list. The list is terminated by the bottom-of-z-order
/// sentinel, so the reported size counts one entry more than the windows.
/// # C: O(N_windows² + N_list)
fn build_hwnd_list(args: &[u64]) -> u64 {
    let (Some(buffer), Some(size_out)) = (crate::nt_dispatch::stack_argument(6),
        crate::nt_dispatch::stack_argument(7)) else { return STATUS_INVALID_PARAMETER; };
    let thread = args[4] as u32 as u64;
    let capacity = args[5] as u32 as usize;
    let window = (args[1] != 0).then_some(args[1]);
    let filter = HwndListFilter {
        window: window.and_then(|hwnd| u32::try_from(hwnd).ok()).and_then(ipc::win32_window::WindowId::from_raw),
        children: args[2] != 0, thread };
    if args[1] != 0 && filter.window.is_none() { return STATUS_INVALID_PARAMETER; }
    let found = owner::hwnd_list_for_current(filter);
    let needed = found.len() + 1;
    if uaccess::put_user_u32(size_out, needed as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    if capacity == 0 || needed > capacity { return STATUS_BUFFER_TOO_SMALL; }
    for (index, window) in found.iter().enumerate() {
        let Some(address) = buffer.checked_add(index as u64 * 8) else { return STATUS_INVALID_PARAMETER; };
        if uaccess::put_user_u64(address, *window as u64).is_err() { return STATUS_INVALID_PARAMETER; }
    }
    let Some(terminator) = buffer.checked_add(found.len() as u64 * 8) else { return STATUS_INVALID_PARAMETER; };
    if uaccess::put_user_u64(terminator, HWND_BOTTOM).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

/// The sentinel that terminates a handle list.
const HWND_BOTTOM: u64 = 1;

/// Fill one property list. A buffer too small still reports the true count.
/// # C: O(N_windows + N_properties)
fn build_prop_list(hwnd: u64, capacity: u32, buffer: u64, count_out: u64) -> u64 {
    if buffer == 0 || count_out == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(properties) = owner::property_list_for_current(hwnd) else { return STATUS_INVALID_PARAMETER; };
    if uaccess::put_user_u32(count_out, properties.len() as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    let writable = properties.len().min(capacity as usize);
    for (index, (data, atom, string)) in properties.iter().take(writable).enumerate() {
        let Some(entry) = buffer.checked_add(index as u64 * PROPERTY_ENTRY_BYTES) else { return STATUS_INVALID_PARAMETER; };
        if uaccess::put_user_u64(entry + PROPERTY_ENTRY_DATA, *data).is_err()
            || uaccess::put_user_u32(entry + PROPERTY_ENTRY_ATOM, *atom as u32).is_err()
            || uaccess::put_user_u32(entry + PROPERTY_ENTRY_STRING, *string as u32).is_err() {
            return STATUS_INVALID_PARAMETER;
        }
    }
    if properties.len() > capacity as usize { return STATUS_BUFFER_TOO_SMALL; }
    STATUS_SUCCESS
}
