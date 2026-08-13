//! Driver firmware-byte lookup.

extern crate alloc;

use alloc::vec::Vec;

const FIRMWARE_PREFIX: &[u8] = b"/lib/firmware/";
const FIRMWARE_NAME_MAX: usize = 255;

/// Load a validated relative firmware name from the mounted root filesystem.
/// # C: O(firmware bytes)
pub fn read(name: &[u8]) -> Option<Vec<u8>> {
    if !valid_name(name) { return None; }
    let mut path = Vec::with_capacity(FIRMWARE_PREFIX.len().checked_add(name.len())?);
    path.extend_from_slice(FIRMWARE_PREFIX);
    path.extend_from_slice(name);
    ext4::rootfs::read_file(&path)
}

/// Accept one non-empty relative path without traversal components. # C: O(name bytes)
pub fn valid_name(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > FIRMWARE_NAME_MAX || name[0] == b'/' { return false; }
    name.split(|byte| *byte == b'/').all(|part| !part.is_empty() && part != b"." && part != b"..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_names_are_relative_and_non_traversing() {
        assert!(valid_name(b"rtl_nic/rtl8125b-2.fw"));
        assert!(!valid_name(b""));
        assert!(!valid_name(b"/rtl_nic/rtl8125b-2.fw"));
        assert!(!valid_name(b"rtl_nic/../rtl8125b-2.fw"));
        assert!(!valid_name(b"rtl_nic//rtl8125b-2.fw"));
    }
}
