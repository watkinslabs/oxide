//! Clipboard ordinal wiring: usercopy and encoding only.
use super::*;
use alloc::vec::Vec;
use ipc::win32_window::ClipboardError;
use crate::nt_window as owner;

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_UNSUCCESSFUL: u64 = 0xc000_0001;
/// A format query that walks off the end answers zero, not an error.
const NO_FORMAT: u64 = 0;
/// A priority query answering that nothing in the list is offered.
const NO_PRIORITY_MATCH: u64 = -1i64 as u64;

fn win_bool(value: bool) -> u64 { value as u64 }

/// # C: O(clipboard owner work plus bounded usercopy)
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    if !claims(ordinal) { return None; }
    Some(match ordinal {
        ADD_FORMAT_LISTENER => win_bool(owner::clipboard_listener(args[0], true).is_ok()),
        REMOVE_FORMAT_LISTENER => win_bool(owner::clipboard_listener(args[0], false).is_ok()),
        CHANGE_CLIPBOARD_CHAIN => win_bool(owner::clipboard_change_chain(args[0], args[1]).unwrap_or(false)),
        COUNT_FORMATS => owner::clipboard_format_count(),
        EMPTY_CLIPBOARD => win_bool(owner::empty_clipboard_for_current()),
        ENUM_FORMATS => owner::clipboard_enum_format(args[0] as u32).map_or(NO_FORMAT, u64::from),
        GET_OWNER => owner::clipboard_owner(),
        GET_OPEN_WINDOW => owner::clipboard_open_window(),
        GET_VIEWER => owner::clipboard_viewer(),
        GET_SEQUENCE_NUMBER => owner::clipboard_sequence(),
        SET_VIEWER => owner::clipboard_set_viewer(args[0]).unwrap_or(0),
        IS_FORMAT_AVAILABLE => win_bool(owner::clipboard_format_available(args[0] as u32)),
        GET_PRIORITY_FORMAT => priority(args[0], args[1] as u32 as i32),
        GET_UPDATED_FORMATS => updated(args[0], args[1] as u32, args[2]),
        GET_FORMAT_NAME => crate::nt_wine_window::atom_raw::kernel::atom_name(args[0] as u32 as u16, args[1], args[2] as u32 as i32),
        SET_DATA => set_data(args[0] as u32, args[1], args[2]),
        GET_DATA => get_data(args[0] as u32, args[1]),
        _ => STATUS_INVALID_PARAMETER,
    })
}

fn priority(list: u64, count: i32) -> u64 {
    if count <= 0 || list == 0 { return NO_PRIORITY_MATCH; }
    let count = (count as usize).min(MAX_PRIORITY_FORMATS);
    let mut formats = Vec::new();
    if formats.try_reserve_exact(count).is_err() { return NO_PRIORITY_MATCH; }
    for index in 0..count {
        let Some(address) = list.checked_add(index as u64 * 4) else { return NO_PRIORITY_MATCH; };
        let Ok(format) = uaccess::get_user_u32(address) else { return NO_PRIORITY_MATCH; };
        formats.push(format);
    }
    owner::clipboard_priority_format(&formats) as i64 as u64
}

fn updated(buffer: u64, size: u32, out_size: u64) -> u64 {
    let Some(capacity) = updated_formats_capacity(buffer, size, out_size) else { return win_bool(false); };
    let formats = owner::clipboard_format_ids();
    if uaccess::put_user_u32(out_size, formats.len() as u32).is_err() { return win_bool(false); }
    if capacity == 0 { return win_bool(formats.is_empty()); }
    if formats.len() > capacity { return win_bool(false); }
    for (index, format) in formats.iter().enumerate() {
        let Some(address) = buffer.checked_add(index as u64 * 4) else { return win_bool(false); };
        if uaccess::put_user_u32(address, *format).is_err() { return win_bool(false); }
    }
    win_bool(true)
}

fn set_data(format: u32, _handle: u64, params: u64) -> u64 {
    if params == 0 { return STATUS_INVALID_PARAMETER; }
    let Ok(data) = uaccess::get_user_u64(params + SET_PARAMS_DATA) else { return STATUS_INVALID_PARAMETER; };
    let Ok(size) = uaccess::get_user_u64(params + SET_PARAMS_SIZE) else { return STATUS_INVALID_PARAMETER; };
    let Ok(cache_only) = uaccess::get_user_u32(params + SET_PARAMS_CACHE_ONLY) else { return STATUS_INVALID_PARAMETER; };
    // A cache-only write records a client-side handle for a format the store
    // already holds. The store keeps no client handles, so it cannot succeed.
    if cache_only != 0 { return STATUS_UNSUCCESSFUL; }
    if size > MAX_FORMAT_BYTES { return STATUS_INVALID_PARAMETER; }
    let bytes = if data == 0 || size == 0 { None } else {
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(size as usize).is_err() { return STATUS_INVALID_PARAMETER; }
        bytes.resize(size as usize, 0);
        if uaccess::copy_from_user(&mut bytes, data).is_err() { return STATUS_INVALID_PARAMETER; }
        Some(bytes)
    };
    match owner::clipboard_set_data(format, bytes.as_deref(), 0) {
        Ok(seqno) => { let _ = uaccess::put_user_u32(params + SET_PARAMS_SEQNO, seqno); STATUS_SUCCESS }
        Err(ClipboardError::NoMemory) => STATUS_INVALID_PARAMETER,
        Err(_) => STATUS_UNSUCCESSFUL,
    }
}

fn get_data(format: u32, params: u64) -> u64 {
    if params == 0 { return 0; }
    let Ok(data) = uaccess::get_user_u64(params + GET_PARAMS_DATA) else { return 0; };
    let Ok(capacity) = uaccess::get_user_u64(params + GET_PARAMS_SIZE) else { return 0; };
    let mut bytes = Vec::new();
    let Ok((from, seqno, stored)) = owner::clipboard_data(format, &mut bytes) else { return 0; };
    let _ = uaccess::put_user_u64(params + GET_PARAMS_SIZE, stored as u64);
    let _ = uaccess::put_user_u32(params + GET_PARAMS_SEQNO, seqno);
    // A delay-rendered format has no bytes here; the caller renders it.
    if stored == 0 || !fits(stored, capacity) || data == 0 { return 0; }
    if uaccess::copy_to_user(data, &bytes).is_err() { return 0; }
    let _ = uaccess::put_user_u32(params + GET_PARAMS_DATA_SIZE, from);
    data
}
