//! Driver firmware-byte lookup.

extern crate alloc;

use alloc::vec::Vec;

/// Ordered filesystem locations accepted for one relative firmware name.
/// # C: const.
pub const FIRMWARE_PREFIXES: [&[u8]; 3] = [b"/lib/firmware/updates/", b"/lib/firmware/", b"/usr/lib/firmware/"];
const FIRMWARE_NAME_MAX: usize = 255;

/// Load a validated relative firmware name from the mounted root filesystem.
/// # C: O(firmware bytes)
pub fn read(name: &[u8]) -> Option<Vec<u8>> {
    read_with(name, ext4::rootfs::read_file)
}

/// Search the canonical firmware locations through one caller-owned reader.
/// The kernel-native loader uses the mounted root filesystem; the Linux ABI
/// facade supplies its initramfs-aware reader without duplicating path policy.
/// # C: O(firmware paths + reader bytes)
pub fn read_with<F: FnMut(&[u8]) -> Option<Vec<u8>>>(name: &[u8], mut reader: F) -> Option<Vec<u8>> {
    if !valid_name(name) { return None; }
    for prefix in FIRMWARE_PREFIXES {
        let mut path = Vec::with_capacity(prefix.len().checked_add(name.len())?);
        path.extend_from_slice(prefix);
        path.extend_from_slice(name);
        if let Some(bytes) = reader(&path) { return Some(bytes); }
    }
    None
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

    #[test]
    fn firmware_search_reaches_usrmerge_after_the_legacy_locations() {
        let mut seen = Vec::new();
        let bytes = read_with(b"rtl_nic/rtl8125b-2.fw", |path| {
            seen.push(path.to_vec());
            (path == b"/usr/lib/firmware/rtl_nic/rtl8125b-2.fw").then(|| b"firmware".to_vec())
        });
        assert_eq!(bytes, Some(b"firmware".to_vec()));
        assert_eq!(seen, [
            b"/lib/firmware/updates/rtl_nic/rtl8125b-2.fw".to_vec(),
            b"/lib/firmware/rtl_nic/rtl8125b-2.fw".to_vec(),
            b"/usr/lib/firmware/rtl_nic/rtl8125b-2.fw".to_vec(),
        ]);
    }
}
