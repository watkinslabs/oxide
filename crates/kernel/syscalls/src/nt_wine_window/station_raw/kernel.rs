//! Window-station and desktop wiring: name decoding, handle table access and
//! the object-information records.
use super::*;
use alloc::{string::String, vec::Vec};
use sched::nt_object::{NtHandle, NtObjectType};
use crate::nt_window as owner;

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const UNICODE_STRING_BUFFER: u64 = 8;

fn win_bool(value: bool) -> u64 { value as u64 }

/// Read an `OBJECT_ATTRIBUTES` name as a UTF-16 string. # C: O(N_name)
fn attribute_name(attributes: u64) -> Option<String> {
    if attributes == 0 { return None; }
    let name = uaccess::get_user_u64(attributes + OBJECT_ATTRIBUTES_NAME).ok()?;
    if name == 0 { return None; }
    let length = uaccess::get_user_u16(name).ok()?;
    if !name_length_ok(length) { owner::report_last_error(ERROR_FILENAME_EXCED_RANGE); return None; }
    let buffer = uaccess::get_user_u64(name + UNICODE_STRING_BUFFER).ok()?;
    if buffer == 0 { return None; }
    let mut text = String::new();
    text.try_reserve(length as usize / 2).ok()?;
    for index in 0..(length as usize / 2) {
        let unit = uaccess::get_user_u16(buffer.checked_add(index as u64 * 2)?).ok()?;
        text.push(char::from_u32(unit as u32)?);
    }
    Some(text)
}

/// Station paths live below one canonical directory, so a bare name given to
/// an open or create call names a station there. # C: O(N_name)
fn station_path(name: &str) -> Option<String> {
    if name.starts_with('\\') { return Some(String::from(name)); }
    let root = crate::nt_desktop_names::INTERACTIVE_STATION;
    let parent = root.rsplit_once('\\').map(|(parent, _)| parent)?;
    let mut path = String::new();
    path.try_reserve(parent.len() + 1 + name.len()).ok()?;
    path.push_str(parent); path.push('\\'); path.push_str(name);
    Some(path)
}

/// A desktop is named below the station the caller's attributes root names,
/// or below the process station when they name none. # C: O(N_name)
fn desktop_path(root: u64, name: &str) -> Option<String> {
    let station = if root == 0 { owner::process_station()? } else { owner::object_by_handle(NtHandle::from_raw(root as u32))? };
    if station.kind() != NtObjectType::WindowStation { return None; }
    let (base, station_name) = owner::object_location(&station)?;
    let mut path = String::new();
    path.try_reserve(base.len() + station_name.len() + name.len() + 2).ok()?;
    path.push_str(&base);
    if !base.ends_with('\\') { path.push('\\'); }
    path.push_str(&station_name); path.push('\\'); path.push_str(name);
    Some(path)
}

/// # C: O(namespace + handles + name)
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    if !claims(ordinal) { return None; }
    Some(match ordinal {
        CREATE_WINDOW_STATION | OPEN_WINDOW_STATION => station(ordinal, args),
        CREATE_DESKTOP_EX => create_desktop(args),
        OPEN_DESKTOP => open_desktop(args[0], args[2] as u32),
        OPEN_INPUT_DESKTOP => open_input_desktop(args[2] as u32, args[1] != 0),
        CLOSE_DESKTOP | CLOSE_WINDOW_STATION => close(args[0]),
        GET_PROCESS_WINDOW_STATION => owner::process_station_handle(),
        SET_PROCESS_WINDOW_STATION => win_bool(owner::set_process_station(NtHandle::from_raw(args[0] as u32))),
        GET_THREAD_DESKTOP => owner::thread_desktop_handle(args[0] as u32),
        SET_THREAD_DESKTOP => win_bool(owner::set_thread_desktop(NtHandle::from_raw(args[0] as u32))),
        SWITCH_DESKTOP => win_bool(owner::switch_desktop(NtHandle::from_raw(args[0] as u32))),
        GET_OBJECT_INFORMATION => object_information(args[0] as u32, args[1] as u32 as i32, args[2], args[3] as u32, args[4]),
        SET_OBJECT_INFORMATION => set_object_information(args[0] as u32, args[1] as u32 as i32, args[2], args[3] as u32),
        BUILD_NAME_LIST => build_name_list(args[0] as u32, args[1] as u32, args[2], args[3]),
        _ => 0,
    })
}

fn station(ordinal: u64, args: &[u64]) -> u64 {
    let Some(name) = attribute_name(args[0]).and_then(|name| station_path(&name)) else { return 0; };
    let access = args[1] as u32;
    let object = if ordinal == CREATE_WINDOW_STATION { owner::create_station(&name) }
        else { owner::open_station(&name) };
    let Some(object) = object else { return 0; };
    owner::open_handle(object, access)
}

fn create_desktop(args: &[u64]) -> u64 {
    let device_length = if args[1] == 0 { 0 } else {
        uaccess::get_user_u16(args[1]).unwrap_or(0)
    };
    let flags = args[3] as u32;
    if !admit_desktop_creation(device_length, args[2], flags) {
        owner::report_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let Some(name) = attribute_name(args[0]) else { return 0; };
    let root = uaccess::get_user_u64(args[0] + OBJECT_ATTRIBUTES_ROOT).unwrap_or(0);
    let Some(path) = desktop_path(root, &name) else { return 0; };
    let station = if root == 0 { owner::process_station() } else { owner::object_by_handle(NtHandle::from_raw(root as u32)) };
    let Some(station) = station else { return 0; };
    let Some(object) = owner::create_desktop_object(&path, station) else { return 0; };
    owner::open_handle(object, desktop_access(args[4] as u32))
}

fn open_desktop(attributes: u64, access: u32) -> u64 {
    let Some(name) = attribute_name(attributes) else { return 0; };
    let root = uaccess::get_user_u64(attributes + OBJECT_ATTRIBUTES_ROOT).unwrap_or(0);
    let Some(path) = desktop_path(root, &name) else { return 0; };
    let Some(object) = owner::open_desktop_object(&path) else { return 0; };
    owner::open_handle(object, desktop_access(access))
}

/// The input desktop is the one the desktop currently switched to; a caller
/// asking for it gets a fresh handle onto that object. # C: O(handles)
fn open_input_desktop(access: u32, inherit: bool) -> u64 {
    let _ = inherit;
    let Some(object) = owner::input_desktop() else { return 0; };
    owner::open_handle(object, desktop_access(access))
}

fn close(handle: u64) -> u64 { win_bool(owner::close_handle(NtHandle::from_raw(handle as u32))) }

/// Write one UTF-16 name or type into a caller's buffer, reporting the size it
/// needs either way. # C: O(N_units)
fn write_units(units: &[u16], info: u64, length: u32, needed: u64, class: i32) -> u64 {
    let bytes = units.len() as u32 * 2;
    if needed != 0 && uaccess::put_user_u32(needed, bytes).is_err() { return win_bool(false); }
    if length < bytes { owner::report_last_error(short_buffer_error(class)); return win_bool(false); }
    for (index, unit) in units.iter().enumerate() {
        let Some(address) = info.checked_add(index as u64 * 2) else { return win_bool(false); };
        if !crate::nt_wine_window::user_write::put_user_u16(address, *unit) { return win_bool(false); }
    }
    win_bool(true)
}

fn object_information(handle: u32, class: i32, info: u64, length: u32, needed: u64) -> u64 {
    if !queryable(class) { owner::report_last_error(ERROR_INVALID_PARAMETER); return win_bool(false); }
    if info == 0 { return win_bool(false); }
    let Some(object) = owner::object_by_handle(NtHandle::from_raw(handle)) else { return win_bool(false); };
    let is_desktop = object.kind() == NtObjectType::Desktop;
    match class {
        UOI_FLAGS => {
            if needed != 0 && uaccess::put_user_u32(needed, USEROBJECTFLAGS_BYTES).is_err() { return win_bool(false); }
            if length < USEROBJECTFLAGS_BYTES { owner::report_last_error(short_buffer_error(class)); return win_bool(false); }
            let inherits = owner::handle_inherits(NtHandle::from_raw(handle));
            if uaccess::put_user_u32(info + USEROBJECTFLAGS_INHERIT as u64, inherits as u32).is_err()
                || uaccess::put_user_u32(info + USEROBJECTFLAGS_FLAGS as u64, owner::object_flags(&object)).is_err() {
                return win_bool(false);
            }
            win_bool(true)
        }
        UOI_TYPE => write_units(type_name(is_desktop), info, length, needed, class),
        _ => {
            let Some((_, name)) = owner::object_location(&object) else { return win_bool(false); };
            let mut units: Vec<u16> = Vec::new();
            if units.try_reserve_exact(name.chars().count() + 1).is_err() { return win_bool(false); }
            units.extend(name.encode_utf16());
            units.push(0);
            write_units(&units, info, length, needed, class)
        }
    }
}

fn set_object_information(handle: u32, class: i32, info: u64, length: u32) -> u64 {
    if info == 0 || !settable(class, length) {
        owner::report_last_error(ERROR_INVALID_PARAMETER);
        return win_bool(false);
    }
    let Ok(flags) = uaccess::get_user_u32(info + USEROBJECTFLAGS_FLAGS as u64) else { return win_bool(false); };
    let Some(object) = owner::object_by_handle(NtHandle::from_raw(handle)) else { return win_bool(false); };
    win_bool(owner::set_object_flags(&object, flags))
}

/// List the desktop names of one station, or the station names when no station
/// handle is given. # C: O(namespace entries + N_names)
fn build_name_list(handle: u32, size: u32, list: u64, out_size: u64) -> u64 {
    /// The record is a size, a count, then the names back to back with a final null.
    const HEADER_BYTES: u32 = 8;
    if list == 0 || out_size == 0 || size <= HEADER_BYTES { return STATUS_INVALID_HANDLE; }
    let names = owner::station_entry_names(NtHandle::from_raw(handle));
    let mut units: Vec<u16> = Vec::new();
    for name in &names {
        if units.try_reserve(name.chars().count() + 1).is_err() { return STATUS_INVALID_HANDLE; }
        units.extend(name.encode_utf16());
        units.push(0);
    }
    let total = HEADER_BYTES + units.len() as u32 * 2 + 2;
    if uaccess::put_user_u32(out_size, total).is_err() { return STATUS_INVALID_HANDLE; }
    if size < total { return crate::nt_wine_window::window_raw::kernel::STATUS_BUFFER_TOO_SMALL; }
    if uaccess::put_user_u32(list, total).is_err() || uaccess::put_user_u32(list + 4, names.len() as u32).is_err() {
        return STATUS_INVALID_HANDLE;
    }
    for (index, unit) in units.iter().chain(core::iter::once(&0)).enumerate() {
        let Some(address) = list.checked_add(HEADER_BYTES as u64 + index as u64 * 2) else { return STATUS_INVALID_HANDLE; };
        if !crate::nt_wine_window::user_write::put_user_u16(address, *unit) { return STATUS_INVALID_HANDLE; }
    }
    STATUS_SUCCESS
}
