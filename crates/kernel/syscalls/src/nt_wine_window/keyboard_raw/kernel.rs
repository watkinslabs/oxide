//! Kernel binding: resolve the calling thread's layout, run the layout tables
//! and copy the answers back.
use ipc::win32_window::kbd_layout;
use crate::nt_window::user_input as owner;
use super::*;



/// Copy one name into a caller buffer, terminated, and answer the characters
/// written. # C: O(N_units)
fn write_name(buffer: u64, units: &[u16], capacity: i32) -> Option<i32> {
    if buffer == 0 { return None; }
    let copied = name_copy_length(units.len(), capacity);
    for (index, unit) in units.iter().take(copied).enumerate() {
        uaccess::copy_to_user(buffer.checked_add((index * 2) as u64)?, &unit.to_le_bytes()).ok()?;
    }
    uaccess::copy_to_user(buffer.checked_add((copied * 2) as u64)?, &[0, 0]).ok()?;
    Some(copied as i32)
}

/// # C: O(KEY_STATE_BYTES)
fn read_key_state(pointer: u64) -> Option<[u8; KEY_STATE_BYTES]> {
    let mut state = [0u8; KEY_STATE_BYTES];
    uaccess::copy_from_user(&mut state, pointer).ok()?;
    Some(state)
}

/// # C: O(N_char_entries)
fn to_unicode(args: &[u64]) -> u64 {
    let (virt, scan, state, buffer, size) = (args[0] as u32, args[1] as u32, args[2], args[3], args[4] as i32);
    if state == 0 || size == 0 { return 0; }
    let Some(keys) = read_key_state(state) else { return 0; };
    if buffer == 0 { return 0; }
    // A key-up transition produces no character but still clears the buffer.
    let character = if scan & SCAN_KEY_UP != 0 { None } else { kbd_layout::vkey_to_wchar(virt, &keys) };
    if uaccess::copy_to_user(buffer, &character.unwrap_or(0).to_le_bytes()).is_err() { return 0; }
    if size > 1 && uaccess::copy_to_user(buffer.saturating_add(2), &[0, 0]).is_err() { return 0; }
    translated_length(character.is_some()) as i64 as u64
}

/// # C: O(N_layouts)
fn layout_list(args: &[u64]) -> u64 {
    let (size, buffer) = (args[0] as i32, args[1]);
    let list = owner::keyboard_layout_list_for_current();
    if size <= 0 || buffer == 0 { return list.len() as u64; }
    let copied = list.len().min(size as usize);
    for (index, layout) in list.iter().take(copied).enumerate() {
        let Some(address) = buffer.checked_add((index * 8) as u64) else { return 0; };
        if uaccess::put_user_u64(address, *layout).is_err() { return 0; }
    }
    copied as u64
}

/// Answer the keyboard layout ordinals. # C: O(layout tables)
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    Some(match ordinal {
        ACTIVATE_KEYBOARD_LAYOUT if args.len() >= 2 => owner::activate_keyboard_layout_for_current(args[0]).unwrap_or(0),
        GET_KEYBOARD_LAYOUT if !args.is_empty() => owner::keyboard_layout_for_current(args[0] as u32),
        GET_KEYBOARD_LAYOUT_LIST if args.len() >= 2 => layout_list(args),
        GET_KEYBOARD_LAYOUT_NAME if !args.is_empty() => {
            let name = ipc::win32_window::layout_name(owner::keyboard_layout_for_current(0));
            let capacity = ipc::win32_window::KL_NAMELENGTH as i32;
            write_name(args[0], &name, capacity).is_some() as u64
        }
        GET_KEY_NAME_TEXT if args.len() >= 3 => {
            let Some(name) = kbd_layout::key_name(args[0] as u32) else { return Some(0); };
            write_name(args[1], &name, args[2] as i32).unwrap_or(0) as i64 as u64
        }
        MAP_VIRTUAL_KEY_EX if args.len() >= 3 => kbd_layout::map_virtual_key(args[0] as u32, args[1] as u32) as u64,
        VK_KEY_SCAN_EX if args.len() >= 2 => kbd_layout::wchar_to_vkey(args[0] as u16)
            .map_or(NO_SUCH_CHARACTER, u64::from),
        TO_UNICODE_EX if args.len() >= 5 => to_unicode(args),
        _ => return None,
    })
}

