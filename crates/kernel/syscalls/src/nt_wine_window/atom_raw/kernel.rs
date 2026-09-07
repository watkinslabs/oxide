//! Atom-name and class-unregistration wiring: usercopy and encoding only.
use super::*;

/// `UNICODE_STRING`: length in bytes, capacity in bytes, then the buffer.
const UNICODE_STRING_LENGTH: u64 = 0;
const UNICODE_STRING_MAXIMUM: u64 = 2;
const UNICODE_STRING_BUFFER: u64 = 8;

/// Write one atom's name into a caller's `UNICODE_STRING`, answering the units
/// written. # C: O(N_atoms + N_name)
pub(crate) fn atom_name(atom: u16, string: u64, maximum_bytes: i32) -> u64 {
    if string == 0 { return 0; }
    let Ok(capacity) = uaccess::get_user_u16(string + UNICODE_STRING_MAXIMUM) else { return 0; };
    let Ok(buffer) = uaccess::get_user_u64(string + UNICODE_STRING_BUFFER) else { return 0; };
    let capacity = if maximum_bytes > 0 { maximum_bytes as u64 as u16 } else { capacity };
    write_name(atom, buffer, capacity)
}

/// Shared by both entries: format the name, fit it to the buffer, and write it
/// with its terminating null. # C: O(N_atoms + N_name)
fn write_name(atom: u16, buffer: u64, capacity_bytes: u16) -> u64 {
    let mut integral = [0u16; MAX_INTEGRAL_NAME];
    let mut owned = alloc::vec::Vec::new();
    let name: &[u16] = if atom < MAXINTATOM {
        let Some(units) = integral_atom_name(atom, &mut integral) else { return 0; };
        &integral[..units]
    } else {
        let Some(found) = crate::nt_window::user_atom_name(atom, &mut owned) else { return 0; };
        let _ = found;
        &owned
    };
    let Some(units) = name_fit(name.len(), capacity_bytes as usize / 2) else { return 0; };
    if buffer == 0 { return 0; }
    for index in 0..units {
        let Some(address) = buffer.checked_add(index as u64 * 2) else { return 0; };
        if !crate::nt_wine_window::user_write::put_user_u16(address, name[index]) { return 0; }
    }
    let Some(terminator) = buffer.checked_add(units as u64 * 2) else { return 0; };
    if !crate::nt_wine_window::user_write::put_user_u16(terminator, 0) { return 0; }
    units as u64
}

/// `NtUserGetAtomName`, whose whole contract is the shared name write.
/// # C: O(N_atoms + N_name)
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    match ordinal {
        GET_ATOM_NAME => Some(atom_name(args[0] as u32 as u16, args[1], 0)),
        _ => None,
    }
}
