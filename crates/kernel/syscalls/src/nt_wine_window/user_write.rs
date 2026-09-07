//! Narrow user stores the win32u records need. The scalar usercopy owner
//! carries the 32- and 64-bit forms; these are the byte and UTF-16 unit forms
//! built on its checked byte copy.
#![cfg(target_os = "oxide-kernel")]

/// Write one UTF-16 unit. # C: O(1)
pub(crate) fn put_user_u16(address: u64, value: u16) -> bool {
    uaccess::copy_to_user(address, &value.to_le_bytes()).is_ok()
}

/// Write one byte. # C: O(1)
pub(crate) fn put_user_u8(address: u64, value: u8) -> bool {
    uaccess::copy_to_user(address, &[value]).is_ok()
}

/// Write one UTF-16 string with its terminator, answering the units written
/// excluding the terminator. # C: O(N_units)
pub(crate) fn put_user_units(address: u64, units: &[u16]) -> Option<usize> {
    for (index, unit) in units.iter().enumerate() {
        if !put_user_u16(address.checked_add(index as u64 * 2)?, *unit) { return None; }
    }
    if !put_user_u16(address.checked_add(units.len() as u64 * 2)?, 0) { return None; }
    Some(units.len())
}
