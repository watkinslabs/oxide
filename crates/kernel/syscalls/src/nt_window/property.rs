//! Raw NtUser window-property adapters (`31fj`).

use super::*;
use ipc::win32_window::{PropertyName, PropertyOrigin, WindowId, WindowProperty, MAX_PROPERTY_NAME};

fn read_name(raw: u64) -> Result<PropertyName, u64> {
    if raw <= u16::MAX as u64 { return Ok(PropertyName::Atom(raw as u16)); }
    if raw == 0 { return Err(STATUS_INVALID_PARAMETER); }
    let mut name = Vec::new();
    for index in 0..=MAX_PROPERTY_NAME {
        let address = raw.checked_add((index * 2) as u64).ok_or(STATUS_INVALID_PARAMETER)?;
        let mut bytes = [0u8; 2];
        uaccess::copy_from_user(&mut bytes, address).map_err(|_| STATUS_INVALID_PARAMETER)?;
        let unit = u16::from_le_bytes(bytes);
        if unit == 0 { return if name.is_empty() { Err(STATUS_INVALID_PARAMETER) } else { Ok(PropertyName::String(name)) }; }
        if index == MAX_PROPERTY_NAME { return Err(STATUS_INVALID_PARAMETER); }
        name.push(unit);
    }
    Err(STATUS_INVALID_PARAMETER)
}

fn validate_window(hwnd: u64) -> Result<WindowId, u64> {
    let window = u32::try_from(hwnd).ok().and_then(WindowId::from_raw).ok_or(STATUS_INVALID_HANDLE)?;
    let cur = sched::live::current().ok_or(STATUS_INVALID_HANDLE)?;
    let group = Arc::clone(&cur.thread_group);
    let entries = GUI.lock();
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))).ok_or(STATUS_INVALID_HANDLE)?;
    entries[index].state.get(window).ok_or(STATUS_INVALID_HANDLE).map(|_| window)
}

fn resolve_name(name: PropertyName, set: bool) -> Option<(u16, PropertyOrigin)> {
    match name {
        PropertyName::Atom(atom) if atom != 0 => Some((atom, PropertyOrigin::Atom)),
        PropertyName::String(name) => {
            let mut atoms = USER_ATOMS.lock();
            if set { atoms.property_atom_for_set(&name).map(|atom| (atom, PropertyOrigin::String)) }
            else { atoms.property_atom_for_lookup(&name).map(|atom| (atom, PropertyOrigin::String)) }
        }
        _ => None,
    }
}

fn with_window<R>(hwnd: u64, action: impl FnOnce(&mut ipc::win32_window::WindowManager, WindowId) -> Result<R, u64>) -> Result<R, u64> {
    let window = validate_window(hwnd)?;
    let cur = sched::live::current().ok_or(STATUS_INVALID_HANDLE)?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))).ok_or(STATUS_INVALID_HANDLE)?;
    action(&mut entries[index].state, window)
}

pub(crate) fn get_prop_for_current(hwnd: u64, name: u64) -> u64 {
    let Ok(name) = read_name(name) else { return 0; };
    let Ok(_) = validate_window(hwnd) else { return 0; };
    let Some((atom, _)) = resolve_name(name, false) else { return 0; };
    with_window(hwnd, |state, window| {
        Ok(state.get_property(window, atom).map_err(|_| STATUS_INVALID_HANDLE)?.unwrap_or(0))
    }).unwrap_or(0)
}

pub(crate) fn set_prop_for_current(hwnd: u64, name: u64, value: u64) -> u64 {
    let Ok(name) = read_name(name) else { return 0; };
    let Ok(_) = validate_window(hwnd) else { return 0; };
    let Some((atom, origin)) = resolve_name(name, true) else { return 0; };
    let result = with_window(hwnd, |state, window| state.set_property(window, atom, origin, value).map_err(|_| STATUS_INVALID_PARAMETER));
    let Ok(previous) = result else {
        if origin == PropertyOrigin::String { USER_ATOMS.lock().release_property_atom(atom); }
        return 0;
    };
    if previous.is_some_and(|entry| entry.origin == PropertyOrigin::String) { USER_ATOMS.lock().release_property_atom(atom); }
    1
}

pub(crate) fn remove_prop_for_current(hwnd: u64, name: u64) -> u64 {
    let Ok(name) = read_name(name) else { return 0; };
    let Ok(_) = validate_window(hwnd) else { return 0; };
    let Some((atom, _)) = resolve_name(name, false) else { return 0; };
    with_window(hwnd, |state, window| Ok(state.remove_property(window, atom).map_err(|_| STATUS_INVALID_HANDLE)?))
        .map(|entry: Option<WindowProperty>| {
            if entry.is_some_and(|value| value.origin == PropertyOrigin::String) { USER_ATOMS.lock().release_property_atom(atom); }
            entry.map_or(0, |value| value.value)
        }).unwrap_or(0)
}
