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
